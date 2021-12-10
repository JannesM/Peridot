# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import time
    
class Transaction:
    """Primitive class that describes a transaction
    """
    # header
    timestamp: bytes # (20)
    script_pub_key: bytes # (33)

    # contents
    sender: bytes # (34)
    receiver: bytes # (34)
    asset: bytes # (tByte) -> Tokens: (10) 000.000000 #6 digest | Hash: (32) sha256

    # signature
    hash: bytes # (32)
    script_sig: bytes # (64)

    def __init__(self, pk, sender, receiver, timestamp=None) -> None:
        if timestamp is None:
            self.timestamp = str(time.time()).encode('utf-8')

        else:
            self.timestamp = str(timestamp).encode('utf-8')
        
        self.script_pub_key = pk
        
        self.sender = sender
        self.receiver = receiver
        self.asset = b'\xa0'

        self.hash = self.calculate_hash()

    def calculate_hash(self) -> bytes:
        buffer = self.timestamp + self.script_pub_key + self.sender + self.receiver + self.asset
        
        return hashlib.sha256(buffer).digest()

    def get_asset(self) -> tuple[bytes, bytes]:
        aType = self.asset[:2]
        if aType == b'\xFF\xF1':
            aContent = float(self.asset[2:].decode())
        elif aType == b'\xFF\xF2':
            aContent = self.asset[2:].hex()

        return (aType, aContent)
    
    def generate_token_asset(self, token: float) -> bytes:
        self.asset = b'\xFF\xF1' + str(token).encode('utf-8')
        self.hash = self.calculate_hash()

    def generate_hash_asset(self, hash) -> bytes:
        self.asset = b'\xFF\xF2' + hash
        self.hash = self.calculate_hash()

    def get_timestamp(self) -> float:
        """Function that converts unix timestamp from bytes to float

        Returns unix timestamp as a floating point number
        """
        return float(self.timestamp.decode())