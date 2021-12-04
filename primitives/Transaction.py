# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hashlib

class Input:
    """Primitive class that describes a transaction input
    """
    refHeight = 0
    refHash = ""
    refIndex = 0

    script_pub_key = ""
    script_sig = ""

    def __init__(self, refHeight, refHash, refIndex, script_pub_key, script_sig) -> None:
        self.refHeight = refHeight
        self.refHash = refHash
        self.refIndex = refIndex
        self.script_pub_key = script_pub_key
        self.script_sig = script_sig


class Output:
    """Primitive class that describes a transaction output
    """
    address = ""
    amount = 0.0

    def __init__(self, address, amount) -> None:
        self.address = address
        self.amount = amount

    
class Transaction:
    """Primitive class that describes a transaction
    """
    # header
    hash = ""
    script_sig = ""

    # contents
    inputs: list[Input] = []
    outputs: list[Output] = []

    def __init__(self, inputs, outputs) -> None:
        self.inputs = inputs
        self.outputs = outputs

    def calculateHash(self) -> str:
        # TODO: updata hashStr to summarize inputs and outputs
        hashStr = "placeholder"
        return hashlib.sha256(hashStr).hexdigest()