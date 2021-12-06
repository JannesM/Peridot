# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from chain import Blockchain
import crypto.P2PKH as Cipher
from mempool import PendingTransactions
from network import Node

import time
import sys
import random


peridot = Blockchain()
pool = PendingTransactions()

sk, pk, addr = Cipher.generate_keys()
ip = '127.0.0.1'
port = random.randint(10000, 10099)
node = Node(ip, port, sk, pk)

if '--other' in sys.argv:
    try:
        port = int(sys.argv[sys.argv.index('--other') + 1])
        node.request_creadentails((ip, port))
        time.sleep(1)
        
    except IndexError:
        print('--other argument without port!')


try:
    while True: 
        time.sleep(1)

except KeyboardInterrupt:
    print("Got interrupt signal!")
    node.stop()
    print("Good bye!")
    