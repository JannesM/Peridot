# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from primitives.Transaction import Transaction

def transactionConsensus(tx: Transaction) -> bool:
    """Function that describes the consensus of a transaction

    Returns true if consensus is valid
    """

    # transaction header
    if not tx.hash or not tx.script_sig:
        return False

    if tx.hash != tx.calculateHash():
        return False

    # inputs and outputs
    if len(tx.inputs) == 0 or len(tx.outputs) == 0:
        return False

    


    return False