# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from primitives.Block import Block
from primitives.Transaction import Transaction
from chain import Blockchain
import crypto.P2PKH as Cipher

def definitionConsensus(tx: Transaction) -> bool:
    """Function that validates the completeness of a transaction

    Args:
        tx (Transaction): transaction to validate

    Returns true if the transaction object is complete
    """
    # transaction header
    if not tx.timestamp or not tx.script_pub_key or not tx.hash or not tx.script_sig:
        print('[Validation] Transaction is missing some attributes!')
        return False

    # inputs and outputs
    if len(tx.inputs) == 0:
        print('[Validation] Transaction has no inputs!')
        return False

    for x in tx.inputs:
        if not x.utxoRef or not x.script_sig:
            print('[Validation] An input is missing some attributes')
            return False

    for x in tx.outputs:
        if not x.address or not x.amount:
            print('[Validation] An output is missing some attributes')
            return False

    return True

def transactionConsensus(tx: Transaction, blockchain: Blockchain) -> bool:
    """Function that describes the internal consensus of a transaction

    Args:
        tx (Transaction): transaction to validate
        chain (Blockchain): the current blockchain

    Returns true if the transaction object is valid
    """

    if tx.hash != tx.calculate_hash():
        return False
    
    
    for input in tx.inputs:
        height, txHash, index = input.decode_utxo_ref()

        for block in blockchain.chain:
            for transaction in block.transactions:
                for sInput in transaction.inputs:
                    if input.utxoRef == sInput.utxoRef:
                        print('[Validation] Double spent warning!')
                        return False
        
        
        block = blockchain.chain[height]        
        prevTx = None
        for transaction in block.transactions:
            if transaction.hash == txHash:
                prevTx = transaction

        if prevTx is not None:
            prevOutput = prevTx.outputs[index]
            if not Cipher.verify_relation(tx.script_pub_key, prevOutput.address, input.script_sig, prevTx.hash):
                print('[Validation] At least one input signature is invalid!')
                return False

        else:
            print('[Validation] The referenced output does not exist!')
            return False

    return True