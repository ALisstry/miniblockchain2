# -*- encoding: utf-8 -*-
# written in python 3.8+
__author__ = 'ctf_creator'

import hashlib, json, rsa, uuid, os, time, random
from flask import Flask, session, redirect, url_for, request
from markupsafe import escape

app = Flask(__name__)
#<hidden>
# this part is hidden from the contestants of the challenge for reducing unnecessary complexity
import pickle
app.secret_key = 'pos_blockchain_ctf_secret_key_2024'
url_prefix = '/<string:prefix>'

# DDCTF\{P0S_H34vy_Ch41n_[0-9a-fA-F]{4}Att@ck_[0-9a-fA-F]{4}\}
valid_url_prefixs = {
    'a1b2c3d4e5f6g': 'P0S_H34vy_Ch41n_',
    'a2b3c4d5e6f7g': 'P0S_H34vy_Ch41n_',
    'a3b4c5d6e7f8g': 'P0S_H34vy_Ch41n_',
    
    'b1c2d3e4f5g6h': 'P0S_H34vy_Ch41n_',
    'b2c3d4e5f6g7h': 'P0S_H34vy_Ch41n_',
    'b3c4d5e6f7g8h': 'P0S_H34vy_Ch41n_',
    
    'c1d2e3f4g5h6i': 'P0S_H34vy_Ch41n_',
    'c2d3e4f5g6h7i': 'P0S_H34vy_Ch41n_',
    'c3d4e5f6g7h8i': 'P0S_H34vy_Ch41n_',
}

def FLAG():
    flag = valid_url_prefixs[request.user_prefix]+session['genesis_block_hash'][4:8]+'Att@ck_'+request.user_prefix[5:8]+session['genesis_block_hash'][12:16]
    try:
        with open('flag.log', 'ab') as f:
            f.write((request.remote_addr + ', ' + flag + '\n').encode())
        try:
            with open('blockchain.log', 'ab') as f:
                f.write((json.dumps(session['blocks']) + '\n').encode())
        except:
            with open('blockchain.log', 'ab') as f:
                f.write(('FAILED ' + flag + '\n').encode())
    except:
        return 'Something went ERROR, please contact admin of DDCTF to get your flag'
    return 'Here is your flag: DDCTF{'+flag+'}'
	
original_app_route = app.route
def new_app_route(url_pattern, **kwargs):
    def __dummy(f):
        def _(*args, **kwargs):
            if kwargs['prefix'] not in valid_url_prefixs: return '404 NOT FOUND', 404
            request.user_prefix = kwargs['prefix']
            del kwargs['prefix']
            if len(args) == 0 and len(kwargs) == 0: return f()
            if len(kwargs) == 0: return f(*args)
            if len(args) == 0: return f(**kwargs)
            return f(*args, **kwargs)
        _.__name__ = str(uuid.uuid4())
        return original_app_route(url_pattern, **kwargs)(_)
    return __dummy
app.route = new_app_route
	
'''
#</hidden>
app.secret_key = '*********************'
url_prefix = '{{URL_PREFIX}}'

def FLAG():
    return 'Here is your flag: DDCTF{******************}'
#<hidden>
'''
#</hidden>

def hash(x):
    if isinstance(x, str):
        x = x.encode()
    return hashlib.sha256(hashlib.md5(x).digest()).hexdigest()
	
def hash_reducer(x, y):
    return hash(hash(x)+hash(y))
	
def has_attrs(d, attrs):
    if type(d) != type({}): raise Exception("Input should be a dict/JSON")
    for attr in attrs:
        if attr not in d:
            raise Exception("{} should be presented in the input".format(attr))

EMPTY_HASH = '0'*64

def addr_to_pubkey(address):
    return rsa.PublicKey(int(address, 16), 65537)
	
def pubkey_to_address(pubkey):
    assert pubkey.e == 65537
    hexed = hex(pubkey.n)
    if hexed.endswith('L'): hexed = hexed[:-1]
    if hexed.startswith('0x'): hexed = hexed[2:]
    return hexed
	
def gen_addr_key_pair():
    pubkey, privkey = rsa.newkeys(384)
    return pubkey_to_address(pubkey), privkey

#<hidden>
'''
#</hidden>
bank_address, bank_privkey = gen_addr_key_pair()
validator1_address, validator1_privkey = gen_addr_key_pair()
validator2_address, validator2_privkey = gen_addr_key_pair()
validator3_address, validator3_privkey = gen_addr_key_pair()
attacker_address, attacker_privkey = gen_addr_key_pair()
treasure_address, treasure_privkey = gen_addr_key_pair()
#<hidden>
'''
# this part is also hidden
KEY_FILENAME = 'pos_blockchain.privkey'
if os.path.isfile(KEY_FILENAME):
    with open(KEY_FILENAME, 'rb') as f:
        obj = pickle.loads(f.read())
    bank_address, bank_privkey = obj['bank']
    validator1_address, validator1_privkey = obj['validator1']
    validator2_address, validator2_privkey = obj['validator2'] 
    validator3_address, validator3_privkey = obj['validator3']
    attacker_address, attacker_privkey = obj['attacker']
    treasure_address, treasure_privkey = obj['treasure']
else:
    bank_address, bank_privkey = gen_addr_key_pair()
    validator1_address, validator1_privkey = gen_addr_key_pair()
    validator2_address, validator2_privkey = gen_addr_key_pair()
    validator3_address, validator3_privkey = gen_addr_key_pair()
    attacker_address, attacker_privkey = gen_addr_key_pair()
    treasure_address, treasure_privkey = gen_addr_key_pair()
    obj = {
        'bank': [bank_address, bank_privkey], 
        'validator1': [validator1_address, validator1_privkey],
        'validator2': [validator2_address, validator2_privkey],
        'validator3': [validator3_address, validator3_privkey],
        'attacker': [attacker_address, attacker_privkey],
        'treasure': [treasure_address, treasure_privkey]
    }
    with open(KEY_FILENAME, 'wb') as f:
        f.write(pickle.dumps(obj))
#</hidden>

def sign_block(block_hash, privkey):
    return rsa.sign(block_hash.encode(), privkey, 'SHA-1').hex()
	
def hash_utxo(utxo):
    return hash_reducer(hash_reducer(utxo['id'], utxo['addr']), str(utxo['amount']))
	
def create_output_utxo(addr_to, amount):
    utxo = {'id': str(uuid.uuid4()), 'addr': addr_to, 'amount': amount}
    utxo['hash'] = hash_utxo(utxo)
    return utxo
	
def hash_tx(tx):
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
    
    return hash_reducer(input_hash, output_hash)
	
def create_tx(input_utxo_ids, output_utxo, privkey_from=None):
    signatures = []
    if privkey_from:
        for utxo_id in input_utxo_ids:
            signatures.append(rsa.sign(utxo_id.encode(), privkey_from, 'SHA-1').hex())
    tx = {'input': input_utxo_ids, 'signature': signatures, 'output': output_utxo}
    tx['hash'] = hash_tx(tx)
    return tx

def get_validator_stake(address, utxos):
    """Calculate the stake amount for a validator"""
    stake = 0
    for utxo in utxos.values():
        if utxo['addr'] == address:
            stake += utxo['amount']
    return stake

def validate_timestamp(block_timestamp, parent_timestamp):
    current_time = int(time.time())
    if block_timestamp <= parent_timestamp:
        raise Exception("Timestamp must be greater than parent")
    if block_timestamp > current_time + 300:  # 5分钟
        raise Exception("Timestamp too far in future")

def select_validator(prev_block_hash, utxos, timestamp):
    """Select validator based on stake-weighted randomness - VULNERABLE TO LONG RANGE ATTACK"""
    # Calculate stakes for all validators
    stakes = {}
    total_stake = 0
    
    # Only consider known validators for simplicity
    validator_addresses = [validator1_address, validator2_address, validator3_address, attacker_address]
    
    for addr in validator_addresses:
        stake = get_validator_stake(addr, utxos)
        if stake > 0:  # Must have some stake to be a validator
            stakes[addr] = stake
            total_stake += stake
    
    if total_stake == 0:
        raise Exception("No validators with stake found")
    
    # Use previous block hash and timestamp as seed for "randomness"
    # This is vulnerable because an attacker can try different timestamps
    seed = hash(prev_block_hash + str(timestamp))
    random_val = int(seed, 16) % total_stake
    
    # Select validator based on stake weight
    cumulative = 0
    for addr, stake in stakes.items():
        cumulative += stake
        if random_val < cumulative:
            return addr
    
    # Fallback (shouldn't reach here)
    return list(stakes.keys())[0]

def calculate_block_weight(block, utxos_at_block):
    """Calculate the weight of a single block based on validator's stake"""
    validator_stake = get_validator_stake(block['validator'], utxos_at_block)
    # Block weight = validator stake * weight multiplier
    # Use a multiplier to make the weight meaningful
    return validator_stake * 100

def calculate_chain_weight(chain):
    """Calculate total weight of a chain (PoS heaviest chain rule)"""
    if not chain:
        return 0
    
    total_weight = 0
    current_utxos = {}
    
    for block in chain:
        # Calculate UTXOs at this block
        for tx in block['transactions']:
            # Remove consumed UTXOs
            for input_utxo_id in tx['input']:
                if input_utxo_id in current_utxos:
                    del current_utxos[input_utxo_id]
            # Add new UTXOs
            for utxo in tx['output']:
                current_utxos[utxo['id']] = utxo
        
        # Calculate block weight based on validator's stake at this point
        block_weight = calculate_block_weight(block, current_utxos)
        total_weight += block_weight
        
        # Store weight in block for debugging
        block['weight'] = block_weight
    
    return total_weight

def hash_block(block):
    tx_hashes = [tx['hash'] for tx in block['transactions']] if block['transactions'] else []
    if tx_hashes:
        tx_hash = tx_hashes[0]
        for i in range(1, len(tx_hashes)):
            tx_hash = hash_reducer(tx_hash, tx_hashes[i])
    else:
        tx_hash = EMPTY_HASH
    return hash_reducer(hash_reducer(hash_reducer(block['prev'], block['validator']), str(block['timestamp'])), tx_hash)
	
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
	
def find_blockchain_tail():
    """Find the tip of the heaviest chain (not longest!)"""
    if not session['blocks']:
        return None
    
    # Find all chain tips (blocks with no children)
    all_hashes = set(session['blocks'].keys())
    child_hashes = set()
    
    for block in session['blocks'].values():
        if block['prev'] in all_hashes:
            child_hashes.add(block['prev'])
    
    tip_hashes = all_hashes - child_hashes
    
    # Among all tips, find the one with heaviest chain
    heaviest_chain = None
    max_weight = -1
    heaviest_tip = None
    
    for tip_hash in tip_hashes:
        chain = get_chain_from_block(tip_hash)
        weight = calculate_chain_weight(chain)
        
        if weight > max_weight:
            max_weight = weight
            heaviest_chain = chain
            heaviest_tip = session['blocks'][tip_hash]
    
    if heaviest_tip:
        heaviest_tip['chain_weight'] = max_weight
    
    return heaviest_tip

def get_chain_from_block(block_hash):
    """Get the chain from genesis to the given block"""
    if block_hash not in session['blocks']:
        return []
    
    chain = []
    current_hash = block_hash
    
    while current_hash != session['genesis_block_hash']:
        block = session['blocks'][current_hash]
        chain.append(block)
        current_hash = block['prev']
    
    # Add genesis block
    chain.append(session['blocks'][session['genesis_block_hash']])
    return chain[::-1]  # Reverse to get chronological order
	
def calculate_utxo(blockchain_tail):
    chain = get_chain_from_block(blockchain_tail['hash'])
    utxos = {}
    for block in chain:
        for tx in block['transactions']:
            for input_utxo_id in tx['input']:
                if input_utxo_id in utxos:
                    del utxos[input_utxo_id]
            for utxo in tx['output']:
                utxos[utxo['id']] = utxo
    return utxos
		
def calculate_balance(utxos):
    balance = {
        bank_address: 0, 
        validator1_address: 0, 
        validator2_address: 0,
        validator3_address: 0,
        attacker_address: 0,
        treasure_address: 0
    }
    for utxo in utxos.values():
        if utxo['addr'] not in balance:
            balance[utxo['addr']] = 0
        balance[utxo['addr']] += utxo['amount']
    return balance

def verify_signature(address, message, signature):
    try:
        return rsa.verify(message.encode(), bytes.fromhex(signature), addr_to_pubkey(address))
    except:
        return False

def verify_utxo_signature(address, utxo_id, signature):
    try:
        return rsa.verify(utxo_id.encode(), bytes.fromhex(signature), addr_to_pubkey(address))
    except:
        return False

def append_block(block):
    has_attrs(block, ['prev', 'validator', 'timestamp', 'transactions', 'signature'])
    
    if type(block['prev']) == type(''): block['prev'] = str(block['prev'])
    if type(block['validator']) == type(''): block['validator'] = str(block['validator'])
    # 修复方案：即使从创世块分叉也要检查验证器
    if block['prev'] not in session['blocks']:
        raise Exception(f"unknown parent block")
    validate_timestamp(block['timestamp'], parent_block['timestamp'])
    parent_block = session['blocks'][block['prev']]
    utxos = calculate_utxo(parent_block)

    # 总是验证验证器选择，包括创世块分叉
    expected_validator = select_validator(block['prev'], utxos, block['timestamp'])
    if block['validator'] != expected_validator:
        raise Exception(f"Invalid validator. Expected {expected_validator}, got {block['validator']}")
    
    # Verify block signature
    block_hash = hash_block({
        'prev': block['prev'],
        'validator': block['validator'], 
        'timestamp': block['timestamp'],
        'transactions': block['transactions'],
        'signature': ''  # Don't include signature in hash
    })
    
    if not verify_signature(block['validator'], block_hash, block['signature']):
        raise Exception("Invalid block signature")
    
    if type(block['transactions']) != type([]): raise Exception('Please put a transaction array in the block')
    new_utxo_ids = set()
    for tx in block['transactions']:
        has_attrs(tx, ['input', 'output', 'signature'])
        
        for utxo in tx['output']:
            has_attrs(utxo, ['amount', 'addr', 'id'])
            if type(utxo['id']) == type(''): utxo['id'] = str(utxo['id'])
            if type(utxo['addr']) == type(''): utxo['addr'] = str(utxo['addr'])
            if type(utxo['id']) != type(''): raise Exception("unknown type of id of output utxo")
            if utxo['id'] in new_utxo_ids: raise Exception("output utxo of same id({}) already exists.".format(utxo['id']))
            new_utxo_ids.add(utxo['id'])
            if type(utxo['amount']) != type(1): raise Exception("unknown type of amount of output utxo")
            if utxo['amount'] <= 0: raise Exception("invalid amount of output utxo")
            if type(utxo['addr']) != type(''): raise Exception("unknown type of address of output utxo")
            try:
                addr_to_pubkey(utxo['addr'])
            except:
                raise Exception("invalid type of address({})".format(utxo['addr']))
            utxo['hash'] = hash_utxo(utxo)
        tot_output = sum([utxo['amount'] for utxo in tx['output']])
        
        if type(tx['input']) != type([]): raise Exception("type of input utxo ids in tx should be array")
        if type(tx['signature']) != type([]): raise Exception("type of input utxo signatures in tx should be array")
        if len(tx['input']) != len(tx['signature']): raise Exception("lengths of arrays of ids and signatures of input utxos should be the same")
        tot_input = 0
        tx['input'] = [str(i) if type(i) == type('') else i for i in tx['input']]
        tx['signature'] = [str(i) if type(i) == type('') else i for i in tx['signature']]
        for utxo_id, signature in zip(tx['input'], tx['signature']):
            if type(utxo_id) != type(''): raise Exception("unknown type of id of input utxo")
            if utxo_id not in utxos: raise Exception("invalid id of input utxo. Input utxo({}) does not exist or it has been consumed.".format(utxo_id))
            utxo = utxos[utxo_id]
            if type(signature) != type(''): raise Exception("unknown type of signature of input utxo")
            
            # CRITICAL VULNERABILITY: Weak signature verification in long-range attacks
            signature_valid = verify_utxo_signature(utxo['addr'], utxo_id, signature)
            
            # # If this is a long-range attack, allow alternative signature verification
            # if not signature_valid and is_long_range_attack:
            #     # In long-range attacks, accept if the validator (attacker) signs the UTXO
            #     # This simulates key compromise or "nothing at stake" scenarios
            #     if verify_utxo_signature(block['validator'], utxo_id, signature):
            #         print(f"[LONG-RANGE ATTACK] Accepting alternative signature from validator {block['validator'][:16]}...")
            #         signature_valid = True
            
            if not signature_valid:
                raise Exception("Signature of input utxo is not valid. You are not the owner of this input utxo({})!".format(utxo_id))
            
            tot_input += utxo['amount']
            del utxos[utxo_id]
        if tot_output > tot_input:
            raise Exception("You don't have enough amount of DDCoins in the input utxo! {}/{}".format(tot_input, tot_output))
        tx['hash'] = hash_tx(tx)
    
    # Create the final block with proper hash
    final_block = create_block(block['prev'], block['validator'], block['timestamp'], block['transactions'], block['signature'])
    final_block['height'] = parent_block['height'] + 1
    
    if len(session['blocks']) > 100: raise Exception('The blockchain is too long. Use ./reset to reset the blockchain')
    if final_block['hash'] in session['blocks']: raise Exception('A same block is already in the blockchain')
    
    # Add the new block first
    session['blocks'][final_block['hash']] = final_block
    
    # HEAVIEST CHAIN LOGIC: Check if this creates a heavier chain
    current_tail = find_blockchain_tail()
    
    # Get the chain containing our new block
    new_chain = get_chain_from_block(final_block['hash'])
    new_chain_weight = calculate_chain_weight(new_chain)
    
    # Compare with current heaviest chain
    if current_tail and current_tail['hash'] != final_block['hash']:
        current_chain = get_chain_from_block(current_tail['hash'])
        current_chain_weight = calculate_chain_weight(current_chain)
        
        print(f"[WEIGHT COMPARISON] New chain weight: {new_chain_weight}, Current chain weight: {current_chain_weight}")
        
        if new_chain_weight > current_chain_weight:
            print(f"[CHAIN REORGANIZATION] New chain is heavier! Reorganizing...")
            # if is_long_range_attack:
            #     print(f"[LONG-RANGE ATTACK SUCCESS] Attacker created heavier chain from genesis!")
    
    session.modified = True
	
def init():
    if 'blocks' not in session:
        session['blocks'] = {}
        session['treasure_unlocked'] = False
    
        # Genesis block - Bank issues initial coins and distributes to validators
        bank_utxo = create_output_utxo(bank_address, 1000)
        validator1_stake = create_output_utxo(validator1_address, 300)
        validator2_stake = create_output_utxo(validator2_address, 200) 
        validator3_stake = create_output_utxo(validator3_address, 100)
        attacker_stake = create_output_utxo(attacker_address, 50)  # Small initial stake
        treasure_utxo = create_output_utxo(treasure_address, 1000000)  # The treasure!
        
        genesis_transaction = create_tx([], [bank_utxo, validator1_stake, validator2_stake, validator3_stake, attacker_stake, treasure_utxo])
        
        # Genesis block doesn't need validator signature
        genesis_block = {
            'prev': EMPTY_HASH,
            'validator': bank_address,
            'timestamp': int(time.time()) - 86400,  # 24 hours ago
            'transactions': [genesis_transaction],
            'signature': ''
        }
        genesis_block['hash'] = hash_block(genesis_block)
        session['genesis_block_hash'] = genesis_block['hash']
        genesis_block['height'] = 0
        session['blocks'][genesis_block['hash']] = genesis_block
        
        # Block 1: Validator1 creates a block
        utxos = calculate_utxo(genesis_block)
        validator = select_validator(genesis_block['hash'], utxos, int(time.time()) - 3600)
        empty_tx = create_tx([], [])
        block_hash = hash_block({
            'prev': genesis_block['hash'],
            'validator': validator,
            'timestamp': int(time.time()) - 3600,
            'transactions': [empty_tx],
            'signature': ''
        })
        
        # Get the private key for the selected validator
        if validator == validator1_address:
            privkey = validator1_privkey
        elif validator == validator2_address:
            privkey = validator2_privkey
        elif validator == validator3_address:
            privkey = validator3_privkey
        else:
            privkey = attacker_privkey
            
        signature = sign_block(block_hash, privkey)
        
        block1 = create_block(genesis_block['hash'], validator, int(time.time()) - 3600, [empty_tx], signature)
        block1['height'] = 1
        session['blocks'][block1['hash']] = block1
        
        session.modified = True
		
def get_balance_of_all():
    init()
    tail = find_blockchain_tail()
    utxos = calculate_utxo(tail)
    return calculate_balance(utxos), utxos, tail
	
@app.route(url_prefix+'/')
def homepage():
    announcement = 'Welcome to the PoS Blockchain CTF! This blockchain uses Proof-of-Stake with HEAVIEST CHAIN rule. '
    announcement += 'Your goal is to unlock the treasure by becoming the dominant validator. '
    announcement += 'Hint: Long-range attacks might work if you can create a heavier chain from genesis... '
    
    balance, utxos, tail = get_balance_of_all()
    if tail:
        weight_info = f'Current chain weight: {getattr(tail, "chain_weight", "calculating...")}'
    else:
        weight_info = 'No chain found'
    
    genesis_block_info = 'Hash of genesis block: ' + session['genesis_block_hash']
    addr_info = ('Addresses - Bank: ' + bank_address + 
                ', Validator1: ' + validator1_address + 
                ', Validator2: ' + validator2_address +
                ', Validator3: ' + validator3_address +
                ', Attacker: ' + attacker_address +
                ', Treasure: ' + treasure_address)
    balance_info = 'Balance of all addresses: ' + json.dumps(balance)
    utxo_info = 'All UTXOs: ' + json.dumps(utxos)
    blockchain_info = 'Blockchain Explorer: ' + json.dumps(session['blocks'])
    view_source_code_link = "<a href='source_code'>View source code</a>"
    return announcement+('<br /><br />\r\n\r\n'.join([view_source_code_link, weight_info, genesis_block_info, addr_info, balance_info, utxo_info, blockchain_info]))
	
@app.route(url_prefix+'/flag')
def getFlag():
    init()
    # Check if attacker controls the treasure
    balance, utxos, tail = get_balance_of_all()
    
    if balance[attacker_address] >= 1000000:  # If attacker has the treasure
        return FLAG()
    
    return f'To get the flag, you need to control the treasure (1,000,000 coins). Attacker currently has {balance[attacker_address]} coins. Current chain weight: {getattr(tail, "chain_weight", "unknown")}. Hint: Try a long-range attack to create a heavier chain!'

def find_enough_utxos(utxos, addr_from, amount):
    collected = []
    for utxo in utxos.values():
        if utxo['addr'] == addr_from:
            amount -= utxo['amount']
            collected.append(utxo['id'])
        if amount <= 0: return collected, -amount
    raise Exception('no enough DDCoins in ' + addr_from)
	
def transfer(utxos, addr_from, addr_to, amount, privkey):
    input_utxo_ids, the_change = find_enough_utxos(utxos, addr_from, amount)
    outputs = [create_output_utxo(addr_to, amount)]
    if the_change != 0:
        outputs.append(create_output_utxo(addr_from, the_change))
    return create_tx(input_utxo_ids, outputs, privkey)

@app.route(url_prefix+'/get_attacker_key')
def get_attacker_key():
    """Give the attacker their private key so they can sign blocks"""
    return f"Attacker private key (for educational purposes): {attacker_privkey.save_pkcs1().hex()}"

@app.route(url_prefix+'/submit_block', methods=['POST'])
def submit_block():
    init()
    try:
        block = json.loads(request.data)
        append_block(block)
        msg = 'Block submitted successfully.'
        
        # Show current chain status
        tail = find_blockchain_tail()
        if tail:
            return msg + f' Current heaviest chain height: {tail["height"]}, weight: {getattr(tail, "chain_weight", "calculating...")}'
        else:
            return msg + ' No chain found.'
        
    except Exception as e:
        return str(e)
		
# if you mess up the blockchain, use this to reset the blockchain.
@app.route(url_prefix+'/reset')
def reset_blockchain():
    if 'blocks' in session: del session['blocks']
    if 'genesis_block_hash' in session: del session['genesis_block_hash']
    if 'treasure_unlocked' in session: del session['treasure_unlocked']
    return 'Blockchain reset.'
	
@app.route(url_prefix+'/source_code')
def show_source_code():
    source = open('pos_blockchain_ctf.py', 'r')
    html = ''
    #<hidden>
    is_hidden = False
    #</hidden>
    for line in source:
        #<hidden>
        if line.strip() == '#</hidden>':
            is_hidden = False
            continue
        if line.strip() == '#<hidden>':
            is_hidden = True
        if is_hidden: continue
        line = line.replace('{{URL_PREFIX}}', '/'+request.user_prefix)
        #</hidden>
        html += line.replace('&','&amp;').replace('\t', '&nbsp;'*4).replace(' ','&nbsp;').replace('<', '&lt;').replace('>','&gt;').replace('\n', '<br />')
    source.close()
    return html

@app.route(url_prefix+'/validator_info')
def validator_info():
    """Show information about validator selection and chain weights"""
    init()
    balance, utxos, tail = get_balance_of_all()
    
    info = "=== PoS Heaviest Chain Information ===<br/>"
    if tail:
        info += f"Current heaviest chain height: {tail['height']}<br/>"
        info += f"Current chain weight: {getattr(tail, 'chain_weight', 'calculating...')}<br/>"
        info += f"Current chain head: {tail['hash']}<br/><br/>"
    
    info += "Validator Stakes (used for block weight calculation):<br/>"
    for addr in [validator1_address, validator2_address, validator3_address, attacker_address]:
        stake = get_validator_stake(addr, utxos)
        name = "Validator1" if addr == validator1_address else \
               "Validator2" if addr == validator2_address else \
               "Validator3" if addr == validator3_address else "Attacker"
        info += f"{name}: {stake} coins<br/>"
    
    info += "<br/>Block Weight Calculation:<br/>"
    info += "- Block Weight = Validator Stake × 100<br/>"
    info += "- Chain Weight = Sum of all block weights in chain<br/>"
    info += "- Heaviest chain becomes the canonical chain<br/><br/>"
    
    info += "Long-Range Attack Strategy:<br/>"
    info += "1. Build alternative chain from genesis<br/>"
    info += "2. Give yourself more stake in early blocks<br/>"
    info += "3. Create blocks with higher validator stakes<br/>"
    info += "4. Make your chain heavier than the current chain<br/>"
    info += "5. Transfer treasure to yourself<br/><br/>"
    
    info += "Hint: Create a genesis-fork where you control more initial stake!<br/>"
    
    return info

@app.route(url_prefix+'/chain_analysis')
def chain_analysis():
    """Analyze all chains and their weights"""
    init()
    
    # Find all chain tips
    all_hashes = set(session['blocks'].keys())
    child_hashes = set()
    
    for block in session['blocks'].values():
        if block['prev'] in all_hashes:
            child_hashes.add(block['prev'])
    
    tip_hashes = all_hashes - child_hashes
    
    info = "=== Chain Analysis ===<br/>"
    info += f"Total blocks: {len(session['blocks'])}<br/>"
    info += f"Chain tips: {len(tip_hashes)}<br/><br/>"
    
    heaviest_weight = 0
    for tip_hash in tip_hashes:
        chain = get_chain_from_block(tip_hash)
        weight = calculate_chain_weight(chain)
        
        info += f"Chain ending at {tip_hash[:16]}...<br/>"
        info += f"  Length: {len(chain)} blocks<br/>"
        info += f"  Weight: {weight}<br/>"
        info += f"  Validator sequence: {' -> '.join([b['validator'][:8] + '...' for b in chain[-5:]])}<br/><br/>"
        
        if weight > heaviest_weight:
            heaviest_weight = weight
    
    info += f"Heaviest chain weight: {heaviest_weight}<br/>"
    
    return info
	
if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5001))
    app.run(debug=False, host='0.0.0.0', port=port)