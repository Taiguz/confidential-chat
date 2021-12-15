#! /usr/bin/env python

import socket
import sys
import time
import threading
import select
import traceback
import rsa
import hashlib
from cryptography.fernet import Fernet

#Iniciando a váriavel que guardará a chave de criptografia recebida pelo servidor
chave_publica_servidor = ''
chave_simetrica = ''
(chave_publica, chave_privada) = rsa.newkeys(2048)
sha = hashlib.sha256()
fernet = None

class Server(threading.Thread):
    def initialise(self, receive):
        self.receive = receive

    def run(self):
        global fernet
        lis = []
        lis.append(self.receive)
        while 1:
            read, write, err = select.select(lis, [], [])
            for socket in read:
                try:
                    mensagem_inteira = socket.recv(1024)
                    mensagem_inteira = mensagem_inteira.decode()
                    mensagem = mensagem_inteira[:len(mensagem_inteira) - 64]
                    mensagem_hash = mensagem_inteira[-64:]
                    #Verificando se a mensagem é integra...
                    if mensagem != '' and mensagem_hash != '':
                        mensagem_decriptada = fernet.decrypt(mensagem.encode())
                        sha.update(mensagem_decriptada)
                        if(sha.hexdigest() != mensagem_hash):
                            raise Exception('Message hash invalid!')
                        print(mensagem_decriptada.decode())
                except:
                    traceback.print_exc(file=sys.stdout)
                    break


class Client(threading.Thread):
    def connect(self, host, port):
        self.sock.connect((host, port))

    def client(self, host, port, msg):
        sent = self.sock.send(msg)

    def run(self):
        global fernet
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            host = input("Enter the server IP:\n#")
            port = int(input("Enter the server Destination Port:\n#"))
            user_name = input("Enter the User Name to be Used:\n#")
        except EOFError:
            print("Error")
            return 1

        print("Connecting...")
        s = ''
        self.connect(host, port)
        time.sleep(1)
        print("Exchanging public keys with server...")
        chave_publica_servidor = rsa.PublicKey.load_pkcs1(format="PEM",keyfile=self.sock.recv(4096))
        self.sock.send(chave_publica.save_pkcs1(format="PEM"))
        try:
            print('Validating...')
            chave_simetrica_criptografada = self.sock.recv(4096)
            self.sock.send(b'ok')
            chave_simetrica_hash = self.sock.recv(4096)
            chave_simetrica = rsa.decrypt(chave_simetrica_criptografada,chave_privada)
            rsa.verify(chave_simetrica,chave_simetrica_hash,chave_publica_servidor)
        except:
            print('Failed to obtain encryption keys.')
            exit(1)
        fernet = Fernet(chave_simetrica)
        print("Starting daemon...")
        server = Server()
        server.initialise(self.sock)
        server.daemon = True
        server.start()
        print("Chat client initialized!")
        while 1:
            msg = input('#')
            if msg == 'exit':
                self.sock.send(b"exit")
                self.sock.close()
                break
            if msg == '':
                continue
            msg = user_name + ': ' + msg
            data = msg.encode()
            #Criptografar a mensagem utilizando a classe fernet instanciada ao receber a primeira mensagem
            #Mandar o hash usando o sha-256 junto com a mensagem
            msg_crypt = fernet.encrypt(data).decode()
            sha.update(data)
            self.client(host, port, (msg_crypt + sha.hexdigest()).encode())
        return (1)


if __name__ == '__main__':
    print("Starting client...")
    cli = Client()
    cli.start()
