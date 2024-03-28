#!/usr/local/bin/python3

# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import argparse
import socket
import zlib
import base64
import os
from coincurve import PrivateKey, PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class VsockStream:
    client_private_key = None  # Store client's private key globally

    """Client"""
    def __init__(self, conn_tmo=5):
        self.conn_tmo = conn_tmo

    def connect(self, endpoint):
        """Connect to the remote endpoint"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.settimeout(self.conn_tmo)
        self.sock.connect(endpoint)

    def send_data(self, data):
        """Send data to a remote endpoint"""
        self.sock.sendall(data)

    def generate_dh_key(self):
        global client_private_key
        print("[+] Generating ECDH public part...")
        private_key = PrivateKey.from_hex(os.urandom(32).hex())
        pub_key = private_key.public_key.format()
        print(pub_key)
        sendable_data = pub_key + zlib.crc32(pub_key).to_bytes(4, byteorder='big')
        b64_data = base64.b64encode(sendable_data)
        print(f"[+] Public part {sendable_data.hex()} Length : {len(b64_data)}")
        client_private_key = private_key.secret
        return pub_key

    def recv_data(self):
        """Receive data from a remote endpoint"""
        while True:
            data = self.sock.recv(1024).decode()
            if not data:
                break
            print(data, end='', flush=True)
            return data
        print()

    def disconnect(self):
        """Close the client socket"""
        self.sock.close()

    def generate_full_dh_key(self, server_key):
        private_key_obj = PrivateKey(client_private_key)
        peer_public_key_obj = PublicKey(server_key)
        shared_key = private_key_obj.ecdh(peer_public_key_obj.public_key)
        print(shared_key)
        return shared_key

    def encrypt_data(self, data, dh_key):
        key = dh_key # Convert DH key to bytes
        iv = os.urandom(16)  # Generate a random IV
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        return iv + ciphertext

def client_handler(args):
    client = VsockStream()
    endpoint = (args.server_cid, args.server_port)
    client.connect(endpoint)

    print("Sending messages to server running on enclave CID %d, port %d" % (args.server_cid, args.server_port))

    client_pub_key = client.generate_dh_key()

    print("Generated Client Public/Private Keys")

    space = " "
    message = "generate" + space + "None" + space + client_pub_key.hex()
    
    client.send_data(message.encode())
    error, server_pub_key = client.recv_data().split(' ')
    print("")
    print(server_pub_key)
    full_dh_key = client.generate_full_dh_key(bytes.fromhex(server_pub_key))
    message = "calculate" + space + "None" + space + client_pub_key.hex()
    client.send_data(message.encode())
    error, response = client.recv_data().split(' ')
    print("")
    print(full_dh_key)
    data_to_send = "Hello, Server!"
    encrypted_data = client.encrypt_data(data_to_send, full_dh_key)
    message = "decrypt_content" + space + encrypted_data.hex() + space + client_pub_key.hex()
    client.send_data(message.encode())
    #check receive data is None and length before split
    error, response = client.recv_data().split(' ')
    print("")
    cred = "bhanukaindia@gmail.com|AKIAUET47FSVPLZCPP42|/+6qtWhX78DC0Af2pGGzkGerGch6UjFY2d+Gl99e|bhanukarc@gmail.com,seshenya@gmail.com"
    encrypted_cred = client.encrypt_data(cred, full_dh_key)
    message = "credentials" + space + encrypted_cred.hex() + space + client_pub_key.hex()
    client.send_data(message.encode())
    error, response = client.recv_data().split(' ')
    print("")
    #client.disconnect()

def send_message(server_address, server_port, message):
    # Connect to the server
    print(server_address, server_port)
    addr = (server_address, server_port)
    client_socket = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    
    # Send the message
    client_socket.sendall(message.encode())
    
    # Receive the response
    response = client_socket.recv(1024).decode()
    
    # Close the connection
    client_socket.close()
    
    return response

def main():
    parser = argparse.ArgumentParser(prog='client')
    parser.add_argument("server_cid", type=int, help="The CID of the enclave running the server")
    parser.add_argument("server_port", type=int, help="The port of the server")

    args = parser.parse_args()

    client_handler(args)

if __name__ == "__main__":
    main()
