# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from primitives.Block import Block
from primitives.Transaction import Transaction
from chain import Blockchain

def definitionConsensus(tx: Transaction) -> bool:
    """Function that validates the completeness of a transaction

    Args:
        tx (Transaction): transaction to validate

    Returns true if the transaction object is complete
    """
    # transaction header
    if not tx.timestamp or not tx.hash or not tx.script_sig:
        return False

    # inputs and outputs
    if len(tx.inputs) == 0 or len(tx.outputs) == 0:
        return False

    for x in tx.inputs:
        if not x.utxoRef or not x.script_pub_key or not x.script_sig:
            return False

    for x in tx.outputs:
        if not x.address or not x.amount:
            return False

    return True

def transactionConsensus(tx: Transaction, chain: Blockchain) -> bool:
    """Function that describes the internal consensus of a transaction

    Args:
        tx (Transaction): transaction to validate
        chain (Blockchain): the current blockchain

    Returns true if the transaction object is valid
    """

    if tx.hash != tx.calculateHash():
        return False
    


    return True