# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import random
import socket
import threading
import hashlib
import crypto.P2PKH as Cipher

class Node(threading.Thread):
    
    sock: socket.socket
    peers = dict()

    tListener: threading.Thread

    sk: bytes
    pk: bytes

    # network general
    flag_accepted = b'\xa1'
    flag_rejected = b'\xa2'

    flag_discovered_peer = b'\xe0'
    flag_pk_request = b'\xf1'
    flag_pk_response = b'\xf2'

    # consensus
    flag_data_transmission = b'\xe1'
    flag_prevote_valid = b'\xe2'
    flag_prevote_nil = b'\xe3'
    flag_precommit_valid = b'\xe4'
    flag_precommit_nil = b'\xe5'

    def __init__(self, ip, port, sk, pk) -> None:
        threading.Thread.__init__(self)

        self.sk = sk
        self.pk = pk

        # node_address = ('0.0.0.0', random.randint(10000, 10099))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))

        print(f'Started node on {ip}:{port}')

    def generate_message(self, flag: bytes, content: bytes):
        # message structure: flag[byte 0:1] + signature[1:65] + content[65:]
        if content is None:
            content = random.randbytes(16)
        
        hash = hashlib.sha256(content).digest()
        sign = Cipher.sign(self.sk, hash)

        message = flag + sign + content
        return message

    def knows_peer(self, addr):
        return addr in self.peers.keys()

    def send_message(self, flag, content, addr):
        self.sock.sendto(self.generate_message(flag, content), addr) # send custom flag and content

    # def request_creadentails(self, addr):
    #     self.send_message(self.flag_pk_request, None, addr)

    def send_creadentails(self, addr):
        self.send_message(self.flag_pk_request, self.pk, addr)
    

    def broadcast_message(self, flag, content):
        for peer in self.peers.keys():
            self.send_message(flag, content, peer)
    
    def publish_peer_update(self, addr):
        ip, port = addr
        self.broadcast_message(self.flag_discovered_peer, (str(ip) + ':' + str(port)).encode('utf-8'))

    def preprocess_message(self, data, addr):
        flag = data[0:1]
        sign = data[1:65]
        content = data[65:]
        isValid = False

        if addr in self.peers.keys():
            public_key = self.peers[addr]
        
            if not public_key or not sign or not flag or not content:
                isValid = False
            else:
                isValid = Cipher.verify_sig(public_key, hashlib.sha256(content).digest(), sign)

            return (flag, content, isValid)

        return (None, None, False)

    def run(self):
        
        while True:
            data, addr = self.sock.recvfrom(2048)

            if data[0:1] == self.flag_pk_request:
                # a net peer wants to participate

                # got signature (64) and public key (33)
                # got a handshake request (other peer sends pk; validate and response with our credentials)
                sig = data[1:65]
                public_key = data[65:]
                #print(addr, ':', public_key.hex())

                if len(sig) != 64 or len(public_key) != 33:
                    # self.send_message(self.flag_rejected, None, addr)
                    #print('Wrong handshake format')
                    continue

                # send response
                if Cipher.verify_sig(public_key, hashlib.sha256(public_key).digest(), sig):
                    
                    if not self.knows_peer(addr):
                        #print('Got something from stranger peer:', addr)

                        self.publish_peer_update(addr)  # expecting no answer from this function
                        self.peers[addr] = public_key
                        print('[Network] New peer: ', addr)
                        self.send_creadentails(addr)
                    else:
                        if self.peers[addr] != public_key:
                            print('Got something from known peer, but pk changed:', addr)

                            del self.peers[addr]
                            self.publish_peer_update(addr)  # expecting no answer from this function
                            self.peers[addr] = public_key
                            print('[Network] Peer updated: ', addr)
                            self.send_creadentails(addr)
                        else:
                            # i know the peer and its current pk. do nothin'
                            pass
                    
                else:
                    print('Rejected:', addr)
                
            else:
                flag, content, isValid = self.preprocess_message(data, addr)                
                if not isValid:
                    print('Got invalid message')
                else:
                    if flag == self.flag_discovered_peer:
                        ip, port = content.decode().split(':')
                        uAddr = (ip, int(port))
                        print(addr, 'says that new peer appeared:', uAddr)

                        self.send_creadentails(uAddr)
                            