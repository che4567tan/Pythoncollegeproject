import socket
import json
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import randomnum
from randomnum import primitive as pr
from randomnum import RandomPrime as rp
from des import DesKey

class SocketConnection:
    def __init__(self):
        self.connect()

    private_key = dh.generate_private_key(
    parameters=dh.generate_parameters(generator=2, key_size=2048),
    )
    public_key = private_key.public_key()

    # Serialize the public key for transmission
    serialized_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    shared_key = private_key.exchange(randomnum)

    def encryption(self):
        dt= [self.id, self.name, self.address]
        e= self.key.encrypt(str(dt).encode("ascii"), padding = True)
        return e 
    def decryption(self, a):
        d= self.key.decrypt(a, padding = True)
        return d
    P= rp()
    G= pr(P)
    pk= [P,G]

    keylist= [b"a@1234ed",b"$5frcddd",b"cd#abcdtx"]

    def connect(self):
        self.host = "100.88.7.119"
        self.port = 1234
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

    def send(self, message):
        request_json = json.dumps(message).encode()
        request_len = len(request_json)
        send_length = request_len.to_bytes(4, byteorder='big')
        self.socket.sendall(send_length)
        self.socket.sendall(request_json)
 
    def receive(self):
        response_len = self.socket.recv(4)
        if response_len:
            response_length = int.from_bytes(response_len, byteorder='big')
            response_json = b''
            while len(response_json) < response_length:
                chunk = self.socket.recv(min(response_length - len(response_json), 1024))
                if not chunk:
                    break
                response_json += chunk
            response = json.loads(response_json.decode())
            return response
        
    def close(self):
        self.socket.close()
