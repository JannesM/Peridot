# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from primitives.Block import Block
import consensus.BlockValidationRules as BlockValidator

from primitives.Transaction import Transaction

class Chain:
    """ Data class that keeps track of the current state of the blockchain
    """

    blockchain: list[Block] = []

    def __init__(self) -> None:
        self.blockchain.append(BlockValidator.genesis())


    def locateTxOutput(self, height, hash, index) -> Transaction:
        txs = self.blockchain[height].transactions
        for tx in txs:
            if tx.hash == hash:
                if len(tx.outputs) > index:
                    return tx.outputs[index]
                else:
                    return None

        return None



