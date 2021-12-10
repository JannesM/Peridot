# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import time
import hashlib
from primitives.Transaction import Transaction

class Block:
    """Primitive class that describes a block in the blockchain
    """
    
    # header
    height: bytes # (20)
    timestamp: bytes # (20)
    prevHash: bytes # (32)
    merkle_root: bytes # (32)
    nonce: bytes # (20)
    hash: bytes # (32)

    # transactions
    transactions: list[Transaction] = [] # referring to primitives/Transaction
    
    def __init__(self, height, prevHash, transactions, timestamp=None, nonce=0) -> None:
        
        self.height = str(height).encode('utf-8')
        
        if timestamp is None:
            self.timestamp = str(time.time()).encode('utf-8')
        else:
            self.timestamp = str(timestamp).encode('utf-8')
        
        
        self.prevHash = prevHash
        self.transactions = transactions
        self.nonce = str(nonce).encode('utf-8')

        self.merkle_root = self.calculate_merkle_root()
        self.hash = self.calculate_hash()

    def calculate_merkle_root(self) -> bytes:
        """Function that reduces all transactions within this block down to a single hash value

        Returns the sha256 representation of all transactions within this block
        """
        
        buffer = bytes()
        for x in self.transactions:
            buffer += x.hash

        return hashlib.sha256(buffer).digest()

    def calculate_hash(self) -> bytes:
        """Function that summarizes the block and compute its hash

        Returns the sha256 representation from this block
        """
    
        hashStr = str(self.height).encode('utf-8') + str(self.timestamp).encode('utf-8') + str(self.nonce).encode('utf-8') + self.merkle_root + self.prevHash
        return hashlib.sha256(hashStr).digest()

    def get_timestamp(self) -> float:
        """Function that converts unix timestamp from bytes to float

        Returns unix timestamp as a floating point number
        """
        return float(self.timestamp.decode())

    def get_height(self) -> float:
        """Function that converts unix timestamp from bytes to float

        Returns unix timestamp as a floating point number
        """
        return int(self.height.decode())        