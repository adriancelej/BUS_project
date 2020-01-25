import socket
import pickle
import binascii
import random
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes

class Network:
    HOST = 'localhost' ##wszystko dzieje się na lokalnym hoście
    BANK_PORT = 55100
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, BANK_PORT))
    sock.listen()
    def receive(self):
        conn, address = self.sock.accept()
        return conn

    def send_client(self, conn, msg):
        conn.send(msg)

    def wait_for_merchant(self, merchant, client):
        print('Waiting for merchant')
        while(not merchant.checkPaymentInitialisation(self.receive(), client)):
            print('Moneta przekazana')
        merchant.lastInformation(self.receive(), client)
        print('Transakcja zakonczona')



class Server:
    network = Network()

    def proces_request(self, conn, client):
        print('Otrzymałem ządanie od klienta!!!')
        auth = Autenticate()
        if(auth.auth(conn.recv(1024), client.getKey(), client.getOrder(), client.getID())):
            bank = Bank()
            conn.send(bank.getSecondMessage(client, bank))
            conn.close()

    def listen(self, client):
        self.proces_request(self.network.receive(), client)

    def listen_merchant(self, merchant, client):
        self.network.wait_for_merchant(merchant, client)


class Token:
    N = 0
    RN = 0
    def __init__(self, n, rn):
        self.N = n
        self.RN = rn

class Bank:
    serialNumber = 451456998
    SK_rn = 73243243824732
    seed = random.seed(serialNumber)
    RN = random.randint(serialNumber, SK_rn)
    SK = b'gt!(ijs%^hbNJAI_'
    def getToken(self, client):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.SK), modes.CBC(self.SK), backend=backend)
        encryptor = cipher.encryptor()
        token = pickle.dumps(Token(self.serialNumber, self.RN))
        padder = padding.PKCS7(128).padder()  # AES wymaga pełnych 128 bitowych bloków danych
        padded_data = padder.update(token) + padder.finalize()  # dopełnienie ostatniego bloku do 128 bitów
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()  # zaszyfrowanie
        client.lastToken = encrypted_data
        return encrypted_data

    def getSecondMessage(self, client, bank):
        token_rt = Token_RT(bank, client)
        encrypted_token_rt, enc_token = token_rt.getToken_RT(bank, client)
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
    def __init__(self, bank, client):
        self.encrypted_Token = bank.getToken(client)
        self.RT = random.randint(bank.serialNumber, bank.SK_rn)

    def getToken_RT(self, bank, client):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(client.client_key), modes.CBC(client.client_key), backend=backend)
        encryptor = cipher.encryptor()
        token_rt = Token_RT(bank, client)
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
    lastToken = None
    n = 100 #liczba monet

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

class Merchant:
    #SPRZEDAWCA
    ID = None #id sprzedawcy
    Km = None #klucz sprzedawcy
    def __init__(self, id, km):
        self.ID = id
        self.Km = km

    def checkPaymentInitialisation(self, conn, client):
        print('Incoming merchant request')
        payment = PaymentInitialisation()
        payment = pickle.loads(conn.recv(1024))
        if client.getID() == payment.IDc and self.ID == payment.IDm:
            print('Merchant: ' + str(payment.IDm) + ' requested payment from client: ' + str(payment.IDc))
            to_hash = bytes(str(payment.w0) + str(payment.IDm) + str(client.client_key), 'utf8')
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(to_hash)
            hashed = digest.finalize()
            if hashed == payment.hash_w0_IDm_Kc:
                print('Received and calculated hash are equals')

                to_hash = bytes(client.lastToken)
                for i in range(0, client.n):
                    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest.update(to_hash)
                    hashed = digest.finalize()
                    to_hash = hashed

                if payment.w0 == hashed:
                    ack = PaymentInicialisationACK(payment.w0, client.getID(), self.ID, True, PaymentInicialisationACK.get_hash(payment.w0, client.getID(), self.Km, payment.Rm, True))
                    conn.send(pickle.dumps(ack))
                    client.n -= 1 ##zmniejsza liczbę monet
                    print('Pieniądze przetransferowane na konto sprzedawcy!!!')
                    if client.n == 0:
                        return True
                    else:
                        return False
            return False

        else:
            print('Client: ' + str(payment.IDc) + ' doesn`t exist!')
            return False

    def lastInformation(self, conn, client):
        info = LastInformation()
        info = pickle.loads(conn.recv(1024))
        if info.IDm == self.ID and info.Wn == client.lastToken:
            if LastInformation.calculate_hash(info.Wn, info.N, self.Km) == info.hash:
                last = LastInformationACK(info.Wn, self.Km)
                conn.send(pickle.loads(last))

class PaymentInitialisation:
    #Pierwsza wiadomość od Sprzedawcy do klienta
    w0 = None #pierwsza moneta
    N = None #numer seryjny
    IDc = None #id klienta
    IDm = None #id sprzedawcy
    Rm = None #losowa liczba
    hash_w0_IDm_Kc = None #SHA256 z w0, IDm i Kc


class PaymentInicialisationACK: ##5 wiadomość z artykułu
    w0 = None
    IDc = None
    IDm = None
    yes = None
    hash = None

    def __init__(self, w, idc, idm, y, hash):
        self.w0 = w
        self.IDc = idc
        self.IDm = idm
        self.yes = y
        self.hash = hash

    def get_hash(w0, IDc, Km, Rm, yes):
        to_hash = bytes(str(w0) + str(IDc) + str(Km) + str(Rm) + str(yes), 'utf8')
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(to_hash)
        hashed = digest.finalize()
        return hashed

class LastInformation:
    Wn = None
    N = None
    IDm = None
    hash = None

    def calculate_hash(wn, N, Km):
        to_hash = bytes(str(wn) + str(N) + str(Km), 'utf8')
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(to_hash)
        return digest.finalize()

class LastInformationACK:
    Wn = None
    hash = None

    def __init__(self, Wn, Km):
        self.Wn = Wn
        to_hash = bytes(str(Wn) + str(Km), 'utf8')
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(to_hash)
        self.hash = digest.finalize()


class Main:
    client = Client(123456789, 987456321, b'ae!r@s9*5gy^&j8l')
    server = Server()
    server.listen(client)
    merchant = Merchant(214365870, b'$#]a/!oq61bh*^%`')
    server.listen_merchant(merchant, client)

Main()