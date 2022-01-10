#!/usr/bin/env python

'''
simple_client.py:
Simple Client Socket using the TLS 1.3 Protocol
'''

import socket
from tls_application import TLSConnection


def client_socket():
    s = socket.socket()
    host = socket.gethostname()
    #host = '18.216.1.168'
    port = 1189
    s.connect((host, port))
    client = TLSConnection(s)
    client.connect(use_psk=True)
    client.write("challenge".encode())
    msg = client.read()
    print(msg.decode('utf-8'))
    psks = client.get_psks()
    s.close()
    s = socket.socket()
    s.connect((host, port))
    client = TLSConnection(s)
    client.connect(use_psk=True, psks=psks, psk_modes=[0,1],
                   early_data='early data'.encode())
    client.write("challenge using resumption".encode())
    msg = client.read()
    print(msg.decode('utf-8'))
    s.close()


if __name__ == '__main__':
    client_socket()
