#!/usr/bin/env python

'''
simple_server.py:
Simple Server Socket using the TLS 1.3 Protocol
'''

import sys
import traceback
import socket
from Cryptodome.Cipher import ChaCha20_Poly1305
from Cryptodome.Random import get_random_bytes
from tls_application import TLSConnection


def server_socket():
    server_static_enc_key = get_random_bytes(ChaCha20_Poly1305.key_size)
    s_socket = socket.socket()
    host = socket.gethostname()
    port = 1189
    # The next setting allows us to reuse the port if still bound
    # By a previous run of the server
    s_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s_socket.bind((host, port))
    s_socket.listen(5)
    while True:
        try:
            c_socket, addr = s_socket.accept()
            print('Got connection from', addr)
            server = TLSConnection(c_socket)
            early_data = server.accept(
                use_psk=True, server_static_key=server_static_enc_key)
            msg = server.read().decode('utf-8')
            if early_data is None:
                response = f'response: {msg}'.encode()
            else:
                early_data_msg = early_data.decode('utf-8')
                response = f'response: {early_data_msg}, {msg}'.encode()
                print(early_data_msg)
            print(msg)
            server.write(response)
            c_socket.close()
        except KeyboardInterrupt:
            print("Shutting Server Down...")
            try:
                c_socket.close()
            except UnboundLocalError:
                print("Did not establish client connection.")
            s_socket.close()
            sys.exit()
        except Exception as e:
            print(e)
            traceback.print_exc()
            print("Something went wrong!")
            try:
                c_socket.close()
            except UnboundLocalError:
                print("Did not establish client connection.")
            s_socket.close()
            server_socket()


if __name__ == '__main__':
    server_socket()
