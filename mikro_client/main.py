from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes

import socket
import pickle
import binascii


class Network:
    HOST = 'localhost' ##wszystko dzieje się na lokalnym hoście
    BANK_PORT = 55100
    CLIENT_PORT = 55200
    MERCHANT_PORT = 55300
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def receive(self):
        return self.sock.recv(1024)

    def send(self, msg):
        self.sock.connect((self.HOST, self.BANK_PORT))
        self.sock.send(msg)

    def send_to_m(self, msg):
        self.sock.connect((self.HOST, self.MERCHANT_PORT))
        self.sock.send(msg)


class Server:
    network = Network()

    def proces_request(self, reqest):
        print(reqest)

    def listen(self, msg):
        self.network.send(msg)
        return self.network.receive()

    def send_to_m(self, msg):
        self.network.send_to_m(msg)


class AuthReq:
    IDc = None
    Oc = None
    hash_Oc_Kc = None

    def __init__(self, id, oc, hash):
        self.IDc = id
        self.Oc = oc
        self.hash_Oc_Kc = hash


class SecondMessage:
    encrypted_token_rt = None
    N = None
    hash = None


class Token_RT:
    encrypted_Token = None
    RT = None


class ThirdMessage:
    w = None
    N = None
    hash = None

    def __init__(self, w, N, hash):
        self.w = w
        self.N = N
        self.hash = hash


class Client:
    IDc = 123456789
    Oc = 987456321
    Kc = b'ae!r@s9*5gy^&j8l'

    def get_order_number(self):
        self.Oc=self.Oc+1

    def send_first_message_to_b(self):
        self.get_order_number()
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes(str(self.Oc)+str(self.Kc), 'utf8'))
        hashed = digest.finalize()
        msg = AuthReq(self.IDc, self.Oc, hashed)
        to_send = pickle.dumps(msg)
        print(msg)
        return to_send

    def checkHash(self, token, N, hash):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes(str(token) + str(N) + str(self.Oc) + str(self.Kc), 'utf8'))
        hashed = digest.finalize()
        print('Obliczony hash: ' + str(binascii.hexlify(hashed)))
        if hash == hashed:
            return True
        else:
            return False

    def get_token_from_b(self, message):
        print('Otrzymano odpowiedź z banku!')
        msg = SecondMessage()
        msg = pickle.loads(message)
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.Kc), modes.CBC(self.Kc), backend=backend)
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(msg.encrypted_token_rt) + decryptor.finalize()

        try:
            unpader = padding.PKCS7(
                128).unpadder()
            decrypted = unpader.update(decrypted) + unpader.finalize()  # usunięcie dodanych danych
        except(ValueError):
            pass

        print('Numer seryjny: ' + str(msg.N))
        tk = Token_RT()
        tk = pickle.loads(decrypted)
        print('Token: ' + str(binascii.hexlify(tk.encrypted_Token)))
        print('Otrzymany hash: ' + str(binascii.hexlify(msg.hash)))

        if self.checkHash(tk.encrypted_Token, msg.N, msg.hash):
            print("Klient wysłał pieniądze")

    def hashW(self, w):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes(w))
        hashed = digest.finalize()
        return hashed

    def send_w_to_merchant(self, i, IDm, n):
        w = self.token
        for x in range(n - i):
             w = self.hashW(w)

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes(str(w) + str(IDm) + str(self.Kc)))
        hashed = digest.finalize()

        message = ThirdMessage(w, self.N, hashed)
        msg = pickle.dumps(message)
        print("Przygotowano W")
        return msg



class Main:
    n=100
    IDm=0
    server = Server()
    client = Client()
    client.get_token_from_b(server.listen(client.send_first_message_to_b()))
    for i in range(n+1):
        print("Start")
        server.send_to_m(client.send_w_to_merchant(i, IDm, n))


Main()