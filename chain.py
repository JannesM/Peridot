# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from primitives.Block import Block
import consensus.BlockValidationRules as BlockValidator

from primitives.Transaction import Transaction

class Blockchain:
    """ Data class that keeps track of the current state of the blockchain
    """

    chain: list[Block] = []

    def __init__(self) -> None:
        #self.chain.append(BlockValidator.genesis())
        pass


    def locateTxOutput(self, height, hash, index) -> Transaction:
        txs = self.chain[height].transactions
        for tx in txs:
            if tx.hash == hash:
                if len(tx.outputs) > index:
                    return tx.outputs[index]
                else:
                    return None

        return None



