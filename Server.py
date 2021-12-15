#! /usr/bin/env python

import socket
import sys
import traceback
import threading
import select
import rsa
from cryptography.fernet import Fernet
from os.path import exists

sockets = []
mensagens_pendentes = []
chaves_publicas = {}

# Gerando chave de criptografia simétrica e assímetrica
# para armazená-las na memória 
chave_simetrica = Fernet.generate_key()
(chave_publica, chave_privada) = rsa.newkeys(2048)

class Mensagem:
    def __init__(self,mensagem,peername):
        self.mensagem = mensagem
        self.peername = peername


class Server(threading.Thread):

    def init(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.bind(('', 5535))
        self.sock.listen(2)
        sockets.append(self.sock)
        print("Server started on port 5535 ")

    def run(self):
        while 1:
            read, write, err = select.select(sockets, [], [], 0)
            for socket_disponivel in read:
                if socket_disponivel == self.sock:
                    # Aceitando nova conexão
                    novo_socket, endereco_conexao = self.sock.accept()
                    sockets.append(novo_socket)
                    print("Connection aceppted from: " + str(endereco_conexao))
                    print("Exchanging public keys with client...")
                    novo_socket.send(chave_publica.save_pkcs1(format="PEM"))
                    chaves_publicas[str(novo_socket.getpeername())] = rsa.PublicKey.load_pkcs1(format="PEM",keyfile=novo_socket.recv(4096))
                    chave_publica_cliente = chaves_publicas[str(novo_socket.getpeername())]
                    chave_simetrica_encriptada = rsa.encrypt(chave_simetrica,chave_publica_cliente)
                    assinatura = rsa.sign(chave_simetrica,chave_privada,'SHA-256')
                    novo_socket.send(chave_simetrica_encriptada)
                    novo_socket.recv(1024)
                    novo_socket.send(assinatura)
                else:
                    try:
                        mensagem_recebida = socket_disponivel.recv(1024)
                        if chaves_publicas[str(socket_disponivel.getpeername())] == '':
                            chaves_publicas[str(socket_disponivel.getpeername())] = mensagem_recebida
                        else:
                            mensagens_pendentes.append(Mensagem(mensagem=mensagem_recebida, peername=str(socket_disponivel.getpeername())))
                    except Exception as error:
                        print(str(error))


class handle_connections(threading.Thread):
    def run(self):
        while 1:
            read, write, err = select.select([], sockets, [], 0)
            for mensagem in mensagens_pendentes:
                for socket_disponivel in write:
                    try:
                        if str(socket_disponivel.getpeername()) == mensagem.peername:
                            continue
                        print("Sending message to ",str(socket_disponivel.getpeername()))
                        socket_disponivel.send(mensagem.mensagem)
                    except Exception as error:
                        print(str(error))
                mensagens_pendentes.remove(mensagem)

if __name__ == '__main__':
    srv = Server()
    srv.init()
    srv.start()
    handle = handle_connections()
    handle.start()
