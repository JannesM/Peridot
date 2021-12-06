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
    height = 0
    timestamp = time.time()
    prevHash = ""
    hash = ""

    # stake
    stake = [] # referring to primitives/Value

    # transactions
    transactions: list[Transaction] = [] # referring to primitives/Transaction
    
    def __init__(self, height, prevHash, stake, transactions) -> None:
        self.height = height
        self.prevHash = prevHash
        self.stake = stake
        self.transactions = transactions
        self.hash = self.calculateHash()

    def calculateHash(self) -> str:
        """Function that summarizes the block and compute its hash

        Returns:
            hash (hex): the sha256 hash of the block
        """
        
        # TODO: adding stake and transactions to hashStr definition
        hashStr = str(self.height) + str(self.timestamp) + self.prevHash
        return hashlib.sha256(hashStr.encode('utf-8')).hexdigest()