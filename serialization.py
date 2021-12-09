# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from primitives.Transaction import Transaction
import base64

FLAG_TX      = b'\x10'

def get_type(data: bytes) -> bytes:
    """Function that analyzes the data type

    Args:
        data (bytes): serialized data

    Returns the descriptive byte of this data package
    """

    data = base64.b64decode(data)
    
    return data[:1]

def encodeTx(tx: Transaction) -> bytes:
    """Function to convert a transaction object into base64 encoded data

    Args:
        tx (Transaction): the transaction to convert

    Returns a byte string containing the base64 encoded conetent
    """
    # timestamp (20), script_pub_key (33), sender (34), receiver (34), asset(1+ 10|32), hash (32), script_sig (64)
    encoded = FLAG_TX + tx.timestamp + tx.script_pub_key
    encoded += tx.sender + tx.receiver + tx.asset
    encoded += tx.hash + tx.script_sig
    
    encoded = base64.b64encode(encoded)
    return encoded

def decodeTx(data: bytes) -> Transaction:
    """Function to convert base64 encoded data into a transaction object

    Args:
        data (bytes): the data to convert

    Returns a transaction object
    """

    data = base64.b64decode(data)
    
    if data[:1] != FLAG_TX:
        return None
    
    ts = float(data[1:21].decode())
    script_pub_key = data[21:54]

    sender = data[54:88]
    receiver = data[88:122]
    
    tx = Transaction(script_pub_key, sender, receiver, timestamp=ts)

    if data[122:123] == b'\xa1':
        # it's a token
        tx.generate_token_asset(float(data[123:133].decode()))
        tx.hash = data[133:165]
        tx.script_sig = data[165:]

    elif data[122:123] == b'\xa2':
        # it's an asset represented by a hash
        tx.generate_hash_asset(data[123:155])
        tx.hash = data[155:187]
        tx.script_sig = data[187:]

    else:
        print('[Serialization]: Wrong asset format!')
        return None

    
    if tx.calculate_hash() != tx.hash:
        print('[Serialization]: Hash comperation failed!')
        return tx

    return tx

    