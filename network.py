

import socket
import threading
import hashlib
import crypto.P2PKH as Cipher

class Node:
    
    sock: socket.socket
    peers = dict()

    tListener: threading.Thread
    pill2kill: threading.Event

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
        self.sk = sk
        self.pk = pk

        # node_address = ('0.0.0.0', random.randint(10000, 10099))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))

        self.pill2kill = threading.Event()
        self.tListener = threading.Thread(target=self.listener, args=(self.pill2kill,), daemon=True)
        self.tListener.start()

        print(f'Started node on {ip}:{port}')

    def generate_message(self, flag: bytes, content: bytes):
        # message structure: flag[byte 0:1] + signature[1:65] + content[65:]
        hash = hashlib.sha256(content).digest()
        sign = Cipher.sign(self.sk, hash)

        message = flag + bytes.fromhex(sign) + content
        return message        

    def knows_peer(self, addr):
        return addr in self.peers.keys()

    def send_message(self, flag, content, addr):
        self.sock.sendto(self.generate_message(flag, content), addr) # send custom flag and content

    def send_flag(self, dflag, addr):
        self.sock.sendto(dflag, addr) # send custom flag


    def request_creadentails(self, addr):
        self.send_flag(self.flag_pk_request, addr)

    def send_creadentails(self, addr):
        self.send_message(self.flag_pk_response, self.pk, addr)
    

    def broadcast_message(self, flag, content):
        for peer in self.peers.keys():
            self.send_message(flag, content, peer)
    
    def publish_peer_update(self, addr):
        ip, port = addr
        self.broadcast_message(self.flag_discovered_peer, (str(ip) + ' ' + str(port)).encode('utf-8'))

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

    def listener(self, p2k):
        while not p2k.wait(1):
            data, addr = self.sock.recvfrom(1024)

            if data[0:1] == self.flag_pk_request: # when other requests me
                # a net peer wants to participate
                print('Hello from', addr)
                self.send_creadentails(addr)
                if not self.knows_peer(addr):
                    self.request_creadentails(addr)

            elif data[0:1] == self.flag_pk_response: # when I request someone
                # got signature (64) and public key (33)
                # got a handshake request (other peer sends pk; validate and response with our credentials)
                sig = data[1:65]
                public_key = data[65:]
                print('Peer response from', addr)

                if len(sig) != 64 or len(public_key) != 33:
                    self.send_flag(self.flag_rejected)

                # send response
                if Cipher.verify_sig(public_key, hashlib.sha256(public_key).digest(), sig):
                    if not self.knows_peer(addr):
                        self.publish_peer_update(addr)
                        self.peers[addr] = public_key
                        print('Accepted connection from', addr)
                        print('Public key is:', public_key)

                else:
                    print('Rejected connection from', addr)
            else:
                flag, content, isValid = self.preprocess_message(data, addr)
                if not isValid:
                    print('Got invalid message')
                else:
                    if flag == self.flag_discovered_peer:
                        print('A peer might has changed...')
                        uAddr = content.decode()
                        ip, port = data.split(b'\x20')
                        uAddr = (ip, port)
                        print('uAddr', uAddr)

                        if not self.knows_peer():
                            self.request_creadentails(uAddr)



    def stop(self):
        self.pill2kill.set()
        self.tListener.join()
        print('Network thread stopped!')