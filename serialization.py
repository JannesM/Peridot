# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from primitives.Transaction import Transaction
from primitives.Block import Block
import base64

FLAG_TX             = b'\xFF\xF0'
FLAG_TX_TOKEN_ASSET = b'\xFF\xF1'
FLAG_TX_HASH_ASSET  = b'\xFF\xF2'
FLAG_TX_ATTR        = b'\xFF\xF3'
FLAG_TX_ARRAY       = b'\xFF\xF4'

FLAG_BLOCK          = b'\xFF\xF5'
FLAG_BLOCK_ATTR     = b'\xFF\xF6'


def get_type(data: bytes) -> bytes:
    """Function that analyzes the data type

    Args:
        data (bytes): serialized data

    Returns the descriptive byte of this data package
    """

    data = base64.b64decode(data)
    
    return data[:1]

def encodeTx(tx: Transaction, b64encoding=True) -> bytes:
    """Function to convert a transaction object into base64 encoded data

    Args:
        tx (Transaction): the transaction to convert

    Returns a byte string containing the base64 encoded content
    """
    # timestamp (20), script_pub_key (33), sender (34), receiver (34), asset(1+ 10|32), hash (32), script_sig (64)
    encoded = FLAG_TX 
    encoded += FLAG_TX_ATTR + tx.timestamp
    encoded += FLAG_TX_ATTR + tx.script_pub_key
    encoded += FLAG_TX_ATTR + tx.sender
    encoded += FLAG_TX_ATTR + tx.receiver
    encoded += FLAG_TX_ATTR + tx.asset
    encoded += FLAG_TX_ATTR + tx.hash
    encoded += FLAG_TX_ATTR + tx.script_sig
    
    if b64encoding:
        encoded = base64.b64encode(encoded)
        return encoded
    else:
        return encoded

def decodeTx(data: bytes, b64decoding=True) -> Transaction:
    """Function to convert base64 encoded data into a transaction object

    Args:
        data (bytes): the data to convert

    Returns a transaction object
    """

    if b64decoding:
        data = base64.b64decode(data)
    
    if data[:2] != FLAG_TX:
        print('[Serialization]: Not a transaction! FLAG is', data[:2])
        return None
    
    data = data.split(FLAG_TX_ATTR)
    
    ts = data[1].decode()
    script_pub_key = data[2]
    sender = data[3]
    receiver = data[4]
    asset = data[5]
    hash = data[6]
    script_sig = data[7]

    tx = Transaction(script_pub_key, sender, receiver, timestamp=ts)
    tx.asset = asset
    tx.hash = hash
    tx.script_sig = script_sig


    return tx

def encodeBlock(block: Block) -> bytes:
    """Function to convert a block object into base64 encoded data

    Args:
        block (Block): the block to convert

    Returns a byte string containing the base64 encoded content
    """

    encoded = FLAG_BLOCK
    encoded += FLAG_BLOCK_ATTR + block.height
    encoded += FLAG_BLOCK_ATTR + block.timestamp
    encoded += FLAG_BLOCK_ATTR + block.prevHash
    encoded += FLAG_BLOCK_ATTR + block.merkle_root
    encoded += FLAG_BLOCK_ATTR + block.nonce
    encoded += FLAG_BLOCK_ATTR + block.hash
    encoded += FLAG_BLOCK_ATTR

    for tx in block.transactions:
        encoded += encodeTx(tx, b64encoding=False) + FLAG_TX_ARRAY

    encoded = base64.b64encode(encoded)
    return encoded

def decodeBlock(data: bytes) -> Block:
    """Function to convert base64 encoded data into a block object

    Args:
        data (bytes): the data to convert

    Returns a block object
    """

    data = base64.b64decode(data)
    
    if data[:2] != FLAG_BLOCK:
        print('[Serialization]: Not a block!')
        return None
    
    data = data.split(FLAG_BLOCK_ATTR)

    height = int(data[1].decode())
    ts = float(data[2].decode())
    prevHash = data[3]
    merkle_root = data[4]
    n = int(data[5].decode())
    hash = data[6]

    raw_trasactions = data[7].split(FLAG_TX_ARRAY)
    raw_trasactions = raw_trasactions[:len(raw_trasactions)-1]
    
    transactions = [decodeTx(tx, b64decoding=False) for tx in raw_trasactions]

    block = Block(height, prevHash, transactions, timestamp=ts, nonce=n)

    if block.merkle_root != merkle_root:
        print('[Serialization]: Block contains incorrect merkle root!')

    if block.hash != hash:
        print('[Serialization]: Block contains incorrect hash!')

    return block


