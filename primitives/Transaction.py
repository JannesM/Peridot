# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import time

class Input:
    """Primitive class that describes a transaction input
    """
    utxoRef = "" # blockHeight.txHash.index

    script_pub_key = ""
    script_sig = ""

    def __init__(self, utxoRef, script_pub_key, script_sig) -> None:
        self.utxoRef = utxoRef
        self.script_pub_key = script_pub_key
        self.script_sig = script_sig

    def __str__(self) -> str:
        """Override default str function

        Returns the sha256 representaion of this class (hex)
        """
        hashStr = self.utxoRef + self.script_pub_key + self.script_sig
        return hashlib.sha256(hashStr.encode("utf-8")).hexdigest()


class Output:
    """Primitive class that describes a transaction output
    """
    address = ""
    amount = 0.0

    def __init__(self, address, amount) -> None:
        self.address = address
        self.amount = amount

    def __str__(self) -> str:
        """Override default str function

        Returns the sha256 representaion of this class (hex)
        """
        hashStr = self.address + str(self.amount)
        return hashlib.sha256(hashStr.encode("utf-8")).hexdigest()

    
class Transaction:
    """Primitive class that describes a transaction
    """
    # header
    timestamp = time.time()
    hash = ""
    script_sig = ""

    # contents
    inputs: list[Input] = []
    outputs: list[Output] = []

    def __init__(self, inputs, outputs) -> None:
        self.inputs = inputs
        self.outputs = outputs
        self.hash = self.calculateHash()

    def calculateHash(self) -> str:
        hashStr = str(self.timestamp) + "".join(str(x) for x in self.inputs) + "".join(str(x) for x in self.outputs)
        return hashlib.sha256(hashStr.encode("utf-8")).hexdigest()