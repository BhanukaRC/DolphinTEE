#!/usr/local/bin/python3

# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# This script was used to communicate with the Enclave and mocking the Dolphin client actions, while running in the same EC2 where the Enclave is
# This is redundant now since the local setup with websocket connections with the EC2 was introduced.

# The script is a little outdated as of now.

import argparse
import socket
import zlib
import base64
import os
from coincurve import PrivateKey, PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time
import extensions
import ec_curves
import signature_algorithms
import constants
import tls
import cbor2

from tls_proxy import Proxy
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from attestation_verifier import verify_attestation_doc

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
        print(f"[INFO] Connected to endpoint {endpoint}")

    def send_data(self, data):
        """Send data to a remote endpoint"""
        self.sock.sendall(data)
        print(f"[INFO] Sent data: {data}")

    def generate_dh_key(self):
        global client_private_key
        print("[INFO] Generating ECDH public key...")
        private_key = PrivateKey.from_hex(os.urandom(32).hex())
        pub_key = private_key.public_key.format()
        sendable_data = pub_key + zlib.crc32(pub_key).to_bytes(4, byteorder='big')
        b64_data = base64.b64encode(sendable_data)
        client_private_key = private_key.secret
        print(f"[INFO] Public key generated: {sendable_data.hex()} Length: {len(b64_data)}")
        return pub_key

    def recv_data(self):
        """Receive data from a remote endpoint"""
        while True:
            data = self.sock.recv(1024).decode()
            if not data:
                break
            return data
        print()

    def disconnect(self):
        """Close the client socket"""
        self.sock.close()
        print("[INFO] Disconnected from the endpoint")

    def generate_full_dh_key(self, server_key):
        private_key_obj = PrivateKey(client_private_key)
        peer_public_key_obj = PublicKey(server_key)
        shared_key = private_key_obj.ecdh(peer_public_key_obj.public_key)
        print(f"[INFO] Shared key established: {shared_key.hex()}")
        return shared_key

    def encrypt_data(self, data, dh_key):
        key = dh_key
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        return iv + ciphertext

    def decrypt_data(self, content, shared_key):
        content = bytes.fromhex(content)
        iv = content[:16]
        ciphertext = content[16:]
        cipher = Cipher(algorithms.AES(shared_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()

def client_handler(client):
    client_pub_key = client.generate_dh_key()

    space = " "
    message = f"generate{space}None{space}{client_pub_key.hex()}"
    client.send_data(message.encode())
    error, server_pub_key = client.recv_data().split(' ')
    full_dh_key = client.generate_full_dh_key(bytes.fromhex(server_pub_key))

    message = f"calculate{space}None{space}{client_pub_key.hex()}"
    client.send_data(message.encode())
    client.recv_data()

    message = f"attest{space}None{space}{client_pub_key.hex()}"
    client.send_data(message.encode())
    received_data = ""
    stop = False
    while True and not stop:
        data_chunk = client.recv_data()
        # If the received data is empty, it means the client has finished sending data
        if len(data_chunk) == 0:
            break
        if len(data_chunk) < 1024:
            stop = True
        # Append the received data to the overall received_data
        received_data += data_chunk
    error, attestation_doc_encrypted = received_data.split(' ')
    attestation_doc_b64 = client.decrypt_data(attestation_doc_encrypted, full_dh_key)
    attestation_doc = base64.b64decode(attestation_doc_b64)

    with open('root.pem', 'r') as file:
        root_cert_pem = file.read()

    data = cbor2.loads(attestation_doc)
    doc = data[2]
    doc_obj = cbor2.loads(doc)
    pcrs = doc_obj['pcrs']
    pcr0 = pcrs[0].hex()

    try:
        verify_attestation_doc(attestation_doc, pcrs=[pcr0], root_cert_pem=root_cert_pem)
        print("[INFO] Attestation verified")
    except Exception as e:
        print(f"[ERROR] Attestation verification failed: {e}")

    public_key_byte = doc_obj['public_key']
    public_key = RSA.import_key(public_key_byte)

    shared_key_str = full_dh_key.hex()
    secret = shared_key_str + "_THIS IS A RANDOM MESSAGE"
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(str.encode(secret))
    ciphertext_b64 = base64.b64encode(ciphertext).decode()
    encrypted_secret = client.encrypt_data(ciphertext_b64, full_dh_key)

    message = f"secret_decryption{space}{encrypted_secret.hex()}{space}{client_pub_key.hex()}"
    client.send_data(message.encode())
    error, ciphertext = client.recv_data().split(' ')
    decrypted_secret = client.decrypt_data(ciphertext, full_dh_key)
    if decrypted_secret == secret:
        print("[INFO] Secret decryption successful")
    else:
        print("[ERROR] Secret decryption failed")

    data_to_send = "Hello, Server!"
    encrypted_data = client.encrypt_data(data_to_send, full_dh_key)
    message = f"decrypt_content{space}{encrypted_data.hex()}{space}{client_pub_key.hex()}"
    client.send_data(message.encode())
    client.recv_data()

    cred = "bhanukadolphin@gmail.com|AKIAUET47FSVJDPSNS6K|8QmJcpkHSzK5DJbkDcKmAFWtj/VY9FKxpwxo/91Q|bhanukarc@gmail.com"
    encrypted_cred = client.encrypt_data(cred, full_dh_key)
    message = f"credentials{space}{encrypted_cred.hex()}{space}{client_pub_key.hex()}"
    client.send_data(message.encode())
    client.recv_data()

    port = 443
    tls_version = tls.TLSV1_2()
    exts = (
        extensions.ServerNameExtension("email.us-east-2.amazonaws.com"),
        extensions.SignatureAlgorithmExtension((
            signature_algorithms.RsaPkcs1Sha256,
            signature_algorithms.RsaPkcs1Sha1,
            signature_algorithms.EcdsaSecp256r1Sha256,
            signature_algorithms.EcdsaSecp384r1Sha384
        )),
        extensions.ECPointFormatsExtension(),
        extensions.ApplicationLayerProtocolNegotiationExtension((constants.EXTENSION_ALPN_HTTP_1_1,)),
        extensions.SupportedGroupsExtension((ec_curves.SECP256R1(),)),
        extensions.SupportedVersionsExtension((tls_version,))
    )

    cipher_suites = (
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES256-SHA384',
        'ECDHE-RSA-AES256-SHA',
        'AES256-GCM-SHA384',
        'AES256-SHA256',
        'AES256-SHA',
        'AES128-SHA',
    )

    ssl_key_logfile = os.getenv('SSLKEYLOGFILE')
    proxy = Proxy("email.us-east-2.amazonaws.com", port, tls_version, cipher_suites, extensions=exts, match_hostname=True, ssl_key_logfile=ssl_key_logfile)

    message = f"client_hello{space}None{space}{client_pub_key.hex()}"
    client.send_data(message.encode())
    error, client_hello = client.recv_data().split(' ')
    client_hello = bytes.fromhex(client_hello)
    proxy.client_hello(client_hello)
    record_bytes, hello_bytes = proxy.server_hello_1()
    certificate_bytes = proxy.server_hello_2()
    next_bytes = proxy.server_hello_3()
    hello_done_bytes = proxy.server_hello_4()
    server_hello = f"{record_bytes.hex()}|{hello_bytes.hex()}|{certificate_bytes.hex()}|{next_bytes.hex()}|{hello_done_bytes.hex()}"
    message = f"server_hello{space}{server_hello}{space}{client_pub_key.hex()}"
    client.send_data(message.encode())
    error, client_finish = client.recv_data().split(' ')
    client_finish = bytes.fromhex(client_finish)
    proxy.client_finish(client_finish)
    record, content = proxy.server_finish()

    server_finish = f"{record.hex()}|{content.hex()}"
    message = f"server_finish{space}{server_finish}{space}{client_pub_key.hex()}"
    client.send_data(message.encode())

    received_data = ""
    stop = False
    while True and not stop:
        data_chunk = client.recv_data()
        # If the received data is empty, it means the client has finished sending data
        if len(data_chunk) == 0:
            break
        if len(data_chunk) < 1024:
            stop = True
        # Append the received data to the overall received_data
        received_data += data_chunk

    error, encrypted_https_request = received_data.split(' ')
    encrypted_https_request = bytes.fromhex(encrypted_https_request)

    proxy.send_application_data(encrypted_https_request)
    record, content = proxy.receive_application_data()
    final_response = f"{record.hex()}|{content.hex()}"
    message = f"receive_application_data{space}{final_response}{space}{client_pub_key.hex()}"
    client.send_data(message.encode())

    received_data = ""
    stop = False
    while True and not stop:
        data_chunk = client.recv_data()
        # If the received data is empty, it means the client has finished sending data
        if len(data_chunk) == 0:
            break
        if len(data_chunk) < 1024:
            stop = True
        # Append the received data to the overall received_data
        received_data += data_chunk

    error, response = received_data.split(' ')
    print(f"[INFO] Final response: {response}")

def send_message(server_address, server_port, message):
    addr = (server_address, server_port)
    client_socket = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    client_socket.sendall(message.encode())
    response = client_socket.recv(1024).decode()
    client_socket.close()
    return response

def main():
    parser = argparse.ArgumentParser(prog='client')
    parser.add_argument("server_cid", type=int, help="The CID of the enclave running the server")
    parser.add_argument("server_port", type=int, help="The port of the server")

    args = parser.parse_args()
    
    total_time = 0
    num_runs = 10
    client = VsockStream()
    endpoint = (args.server_cid, args.server_port)
    client.connect(endpoint)

    for _ in range(num_runs):
        start_time = time.time()
        client_handler(client)
        end_time = time.time()
        elapsed_time = end_time - start_time
        total_time += elapsed_time
        print(f"[INFO] Elapsed time for run {_+1}: {elapsed_time} seconds")

    client.disconnect()

    average_time = total_time / num_runs
    print(f"[INFO] Average elapsed time over {num_runs} runs: {average_time} seconds")

if __name__ == "__main__":
    main()
