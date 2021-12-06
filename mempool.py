# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

class PendingTransactions:

    pending_transactions: list[bytes] = []

    def __init__(self) -> None:
        pass

    def next(self) -> bytes:
        if len(self.pending_transactions) > 0:
            return self.pending_transactions.pop(0) 

        return None

    def add(self, tx: bytes) -> None:
        self.pending_transactions.append(tx)
