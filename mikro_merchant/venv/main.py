from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes

import socket
import pickle
import json


class Network:
    HOST = 'localhost'  ##wszystko dzieje się na lokalnym hoście
    MERCHANT_PORT = 55300
    BANK_PORT = 55100
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, MERCHANT_PORT))
    sock.listen()

    def receive(self):
        conn, address = self.sock.accept()
        return conn

    def receive_from_b(self):
        return self.sock.recv(1024)

    def send(self, msg):
        self.sock.connect((self.HOST, self.BANK_PORT))
        self.sock.send(msg)


class Server:
    network = Network()

    def listen(self):
        return self.network.receive()

    def send_w(self):
        self.network.send(msg)
        return self.network.receive_from_b()



class Message_from_client:
    w = None
    N = None
    hash = None
    def __init__(self, w, N, hash):
        self.w = w
        self.N = N
        self.hash = hash


class Message_to_B:
    w = None
    N = None
    IDc = None
    IDm = None
    Rm = None
    Proof = None
    def __init__(self, w, N, IDc, IDm, Rm, Proof):
        self.w = w
        self.N = N
        self.IDc = IDc
        self.IDm = IDm
        self.Rm = Rm
        self.Proof = Proof



class Message_from_B:
    w = None
    IDc = None
    IDm = None
    ans = None
    hash = None
    def __init__(self, w, IDc, IDm, ans, hash):
        self.w = w
        self.IDc = IDc
        self.ans = ans
        self.hash = hash


class Confirmation_message:
    w = None
    N = None
    IDm = None
    hash = None
    def __init__(self, w, N, IDm, hash):
        self.w = w
        self.N = N
        self.IDm = IDm
        self.hash = hash


class Confirmation_response:
    w = None
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
        message = Message_to_B(self.ws(0), self.N, IDc, self.IDm, Rm, self.proofs(0))
        msg = pickle.dumps(message)
        return msg

    def checkHash(self, w, ans, IDc, hash):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes(str(w) + str(IDc) + str(self.Km) + str(self.Rm) + str(ans), 'utf8'))
        hashed = digest.finalize()
        if hash == hashed:
            self.ws.pop(0)
            self.proofs.pop(0)
            return True
        else:
            return False

    def get_response_from_b(self, message, IDc):
        msg = pickle.loads(message)
        if self.checkHash(msg.w, msg.ans, IDc, msg.hash):
            print("Pieniądze przesłane")

    def send_confirmation(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes(str(self.w(0)) + str(self.N) + str(self.Km), 'utf8'))
        hashed = digest.finalize()
        mesage = Confirmation_message(self.w(0), self.N, self.IDm, hashed)
        print("tutaj wysyłanie")

    def check_response(self, message):
        msg = pickle.loads(message)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes(str(message.w) + str(self.Km), 'utf8'))
        hashed = digest.finalize()
        if msg.hash == hashed:
            print("Transakcja zakończona pomyślnie")
            self.N = None
            self.ws = None
            self.proofs = None
            self.Rm = None


class Main:
    IDc = 0
    n = 100
    server = Server()
    merchant = Merchant()
    for i in range(n+1):
        merchant.get_w_and_proof(server.listen())
    for i in range(n):
        merchant.get_response_from_b(server.send_w(merchant.send_w0_to_b()))
    merchant.check_response(server.send_w(merchant.send_confirmation()))




Main()