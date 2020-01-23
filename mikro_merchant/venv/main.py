from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes

import socket
import pickle
import json


class Network:
    HOST = 'localhost'  ##wszystko dzieje się na lokalnym hoście
    BANK_PORT = 55100
    CLIENT_PORT = 55200
    MERCHANT_PORT = 55300
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, CLIENT_PORT))
    sock.listen()

    def receive(self):
        conn, address = self.sock.accept()
        data = conn.recv(1024)
        return data


class Server:
    network = Network()

    def proces_request(self, reqest):
        print(reqest)
        ##json.loads(reqest)

    def listen(self):
        while (True):
            self.proces_request(self.network.receive())


class Message_from_client:
    w = None
    N = None
    hash = None


class Message_to_B:
    w = None
    N = None
    IDc = None
    IDm = None
    Rm = None
    Proof = None


class Message_from_B:
    w = None
    IDc = None
    IDm = None
    ans = None
    hash = None


class Confirmation_message:
    w = None
    N = None
    IDm = None
    hash = None


class Merchant:
    IDm = 0
    Km = None
    N = None
    ws = None
    proofs = None
    Rm = 54312

    def get_w_and_proof(self, message):
        msg = pickle.loads(message)
        self.ws.append(msg.w)
        if self.N != msg.N:
            self.N = msg.N
        self.proofs.append(msg.hash)

    def send_w0_to_b(self, IDc):
        message = Message_to_B(w=self.ws(0), N=self.N, IDc=IDc, IDm=self.IDm, Rm=Rm, Proof=self.proofs(0))
        msg = pickle.dumps(message)
        self.ws.pop(0)
        self.proofs.pop(0)
        print(msg)

    def checkHash(self, w, ans, IDc, hash):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes(str(w) + str(IDc) + str(self.Km) + str(self.Rm) + str(ans), 'utf8'))
        hashed = digest.finalize()
        if hash == hashed:
            return True
        else:
            return False

    def get_response_from_b(self, message, IDc):
        msg = pickle.loads(message)
        if self.checkHash(msg.w, msg.ans, IDc, msg.hash):
            print("Pieniądze przesłane")

    def send_confirmation(self):


class Main:
    state = "prepaid"
    IDc = 0
    n = 10
    server = Server()
    server.listen()
    if state == "prepaid":
        state = "wait for b"
    elif state == "wait for b":
        state = "micropayment"
    else:
        state = "prepaid"


Main()