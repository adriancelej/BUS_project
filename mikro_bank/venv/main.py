import socket
import pickle
import binascii
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes

class Network:
    HOST = 'localhost' ##wszystko dzieje się na lokalnym hoście
    BANK_PORT = 55100
    CLIENT_PORT = 55200
    MERCHANT_PORT = 55300
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, BANK_PORT))
    sock.listen()
    def receive(self):
        conn, address = self.sock.accept()
        data = conn.recv(1024)
        self.sock.close()
        return data
    def send_client(self, msg):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.HOST, self.CLIENT_PORT))
        self.sock.send(msg)

class Server:
    network = Network()

    def proces_request(self, reqest, client):
        print('Otrzymałem ządanie!!!')
        auth = Autenticate()
        if(auth.auth(reqest, client.getKey(), client.getOrder(), client.getID())):
            bank = Bank()
            self.network.send_client(bank.getSeconMessage(client))

    def listen(self, client):
        self.proces_request(self.network.receive(), client)

class Token:
    N = 0
    RN = 0
    def __init__(self, n, rn):
        self.N = n
        self.RN = rn

class Bank:
    serialNumber = 451456998
    SK_rn = 73243243824732;
    seed = random.seed(serialNumber)
    RN = random.randint(serialNumber, SK_rn)
    SK = b'gt!(ijs%^hbNJAI_'
    def getToken(self):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.SK), modes.CBC(self.SK), backend=backend)
        encryptor = cipher.encryptor()
        token = pickle.dumps(Token(self.serialNumber, self.RN))
        padder = padding.PKCS7(128).padder()  # AES wymaga pełnych 128 bitowych bloków danych
        padded_data = padder.update(token) + padder.finalize()  # dopełnienie ostatniego bloku do 128 bitów
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()  # zaszyfrowanie
        return encrypted_data

    def getSeconMessage(self, client):
        token_rt = Token_RT()
        encrypted_token_rt, enc_token = token_rt.getToken_RT(client.getKey())
        order = client.getOrder() + 1
        to_hash = bytes(str(enc_token) + str(self.serialNumber) + str(order) + str(client.getKey()), 'utf8')
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(to_hash)
        hashed = digest.finalize()
        print('Pobrano środki z konta')
        print('Token: ' + str(binascii.hexlify(enc_token)))
        print('Numer seryjny: ' + str(self.serialNumber))
        print('Hash: ' + str(binascii.hexlify(hashed)))
        return pickle.dumps(SecondMessage(encrypted_token_rt, self.serialNumber, hashed))


class AuthReq:
    IDc = 0
    Oc = 0
    hash_Oc_Kc = b'0'
    def __init__(self, id, oc, hash):
        self.IDc = id
        self.Oc = oc
        self.hash_Oc_Kc = hash

    def getID(self):
        return self.IDc

    def getHash(self):
        return self.hash_Oc_Kc

    def getOc(self):
        return self.Oc

class Token_RT:
    encrypted_Token = None
    RT = None
    def __init__(self):
        bank = Bank()
        self.encrypted_Token = bank.getToken()
        self.RT = random.randint(bank.serialNumber, bank.SK_rn)

    def getToken_RT(self, key):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(key), backend=backend)
        encryptor = cipher.encryptor()
        token_rt = Token_RT()
        token = pickle.dumps(token_rt)
        padder = padding.PKCS7(128).padder()  # AES wymaga pełnych 128 bitowych bloków danych
        padded_data = padder.update(token) + padder.finalize()  # dopełnienie ostatniego bloku do 128 bitów
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()  # zaszyfrowanie
        return encrypted_data, token_rt.encrypted_Token

class Autenticate:
    def auth(self, request, client_key, client_order, client_id):
        req = AuthReq(0, 0, b'0')
        req = pickle.loads(request)
        order = client_order + 1
        to_hash = bytes(str(order) + str(client_key), 'utf8')
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(to_hash)
        hashed = digest.finalize()
        print('ID klienta: ' + str(req.getID()))
        print('Przesłany hash Oc, Kc: ' + str(binascii.hexlify(req.getHash())))
        print('Numer zamówienia: ' + str(req.getOc()))
        print('Obliczony hash: ' + str(binascii.hexlify(hashed)))

        if client_id == req.getID():
            print('Sprawdzanie...')
            if req.getHash() == hashed:
                print('Klient: ' + str(client_id) + ' uwierzytelniony')
                return True
            else:
                return False

class SecondMessage:
    encrypted_token_rt = None
    N = None
    hash = None
    def __init__(self, enc_tok, n, ha):
        self.encrypted_token_rt = enc_tok
        self.N = n
        self.hash = ha


class Client:
    ID_client = 0
    order_num = 0
    client_key = b'0'

    def __init__(self, id, ord_num, key):
        self.ID_client = id
        self.order_num = ord_num
        self.client_key =key
    
    def getKey(self):
        return self.client_key

    def getOrder(self):
        return self.order_num

    def getID(self):
        return self.ID_client


class Main:
    client = Client(123456789, 987456321, b'ae!r@s9*5gy^&j8l')
    server = Server()
    server.listen(client)



Main()