#!/usr/bin/env python

'''
simple_client.py:
Simple Client Socket using the TLS 1.3 Protocol
'''

import socket
from tls_application import TLSConnection


def client_socket():
    s = socket.socket()
    #host = socket.gethostname()
    #host = '10.5.214.213'
    host = '127.0.0.1'
    port = 1189
    s.connect((host, port))
    client = TLSConnection(s)
    client.connect(use_psk=True)
    client.write("challenge".encode())
    msg = client.read()
    print(msg.decode('utf-8'))
    psks = client.get_psks()
    s.close()
    # Done with first try
    print(f"Client closed with #psks {len(psks)}")
    s = socket.socket()
    s.connect((host, port))
    client = TLSConnection(s)
    client.connect(use_psk=True, psks=psks, psk_modes=[0,1])
    client.write("challenge using resumption".encode())
    msg = client.read()
    print(msg.decode('utf-8'))
    psks = client.get_psks()
    s.close()
    # Done with second try
    print(f"Client closed with #psks {len(psks)} and now starting with early data")
    msg2 = "challenge resumption"
    if len(psks) > 0:
        msg2 = "challenge using new resumption key"
    # Another try
    s = socket.socket()
    s.connect((host, port))
    client = TLSConnection(s)
    client.connect(use_psk=True, psks=psks, psk_modes=[0,1],
                   early_data='early data'.encode())
    client.write(msg2.encode())
    msg = client.read()
    print(msg.decode('utf-8'))
    s.close()
    # Another try
    s = socket.socket()
    s.connect((host, port))
    client = TLSConnection(s)
    client.connect(use_psk=True, psks=psks, psk_modes=[0,1],
                   early_data='last early data'.encode())
    client.write(msg2.encode())
    msg = client.read()
    print(msg.decode('utf-8'))
    s.close()


if __name__ == '__main__':
    client_socket()
