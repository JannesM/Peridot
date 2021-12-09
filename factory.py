# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import threading
from chain import Blockchain
from mempool import PendingTransactions

import consensus.TransactionValidationRules as TxValidator
from primitives.Block import Block

class BlockFactory(threading.Thread):

    chain: Blockchain
    pool: PendingTransactions
    addr: bytes

    interrupt: threading.Event

    def __init__(self, addr, chain, pool) -> None:
        threading.Thread.__init__(self)

        self.addr = addr
        self.chain = chain
        self.pool = pool


    def run(self):
        while True:
            block_tx_size = 0
            valid_tx = []

            next_tx = self.pool.next()
            while block_tx_size < 1024 and next_tx is not None:
                tx = 


            while not self.interrupt.wait(1):
                pass

    