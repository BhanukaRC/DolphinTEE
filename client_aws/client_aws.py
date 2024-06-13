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

import extensions
import ec_curves
import signature_algorithms
import constants
import tls

from tls_proxy import Proxy

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

    def decrypt_data(self, content, shared_key):
        print("shared_key", shared_key)
        content = bytes.fromhex(content)
        print("content", content)
        iv = content[:16]  # Extract IV from the beginning of the ciphertext
        ciphertext = content[16:]  # Extract ciphertext after the IV
        cipher = Cipher(algorithms.AES(shared_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        print("plaintext", plaintext)
        plaintext = plaintext.decode()
        print("plaintext", plaintext)
                    
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
    cred = "bhanukadolphin@gmail.com|AKIAUET47FSVJDPSNS6K|8QmJcpkHSzK5DJbkDcKmAFWtj/VY9FKxpwxo/91Q|bhanukarc@gmail.com"
    encrypted_cred = client.encrypt_data(cred, full_dh_key)
    message = "credentials" + space + encrypted_cred.hex() + space + client_pub_key.hex()
    client.send_data(message.encode())
    error, response = client.recv_data().split(' ')
    print("")
    
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
        extensions.ApplicationLayerProtocolNegotiationExtension((
        constants.EXTENSION_ALPN_HTTP_1_1,
        # constants.EXTENSION_ALPN_HTTP_2,
        )),
        extensions.SupportedGroupsExtension((ec_curves.SECP256R1(),)),
        extensions.SupportedVersionsExtension((tls_version,)),
        # extensions.SessionTicketExtension()
        # extensions.SignedCertificateTimestampExtension(),
        # extensions.StatusRequestExtension()
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
    proxy = Proxy("email.us-east-2.amazonaws.com", port, tls_version, cipher_suites, extensions=exts, match_hostname=True,
                  ssl_key_logfile=ssl_key_logfile)
    
    message = "client_hello" + space + "None" + space + client_pub_key.hex()
    client.send_data(message.encode())
    error, client_hello = client.recv_data().split(' ')
    print("")
    client_hello = bytes.fromhex(client_hello)
    proxy.client_hello(client_hello)
    record_bytes, hello_bytes = proxy.server_hello_1()
    certificate_bytes = proxy.server_hello_2()
    next_bytes = proxy.server_hello_3()
    hello_done_bytes = proxy.server_hello_4()
    print(len(record_bytes))
    print(len(hello_bytes))
    print(len(certificate_bytes))
    print(len(next_bytes))
    print(len(hello_done_bytes))
    server_hello = record_bytes.hex() + '|' + hello_bytes.hex() + '|' + certificate_bytes.hex() + '|' + next_bytes.hex() + '|' + hello_done_bytes.hex()
    message = "server_hello" + space + server_hello + space + client_pub_key.hex()
    client.send_data(message.encode())
    error, client_finish = client.recv_data().split(' ')
    print("")
    client_finish = bytes.fromhex(client_finish)
    
    proxy.client_finish(client_finish)
    record, content = proxy.server_finish()
    
    server_finish = record.hex() + '|' + content.hex()
    message = "server_finish" + space + server_finish + space + client_pub_key.hex()
    client.send_data(message.encode())
    
    received_data = ""
    stop = False
    while True and not stop:
        data_chunk = client.recv_data()
        print("")
        # If the received data is empty, it means the client has finished sending data
        if len(data_chunk) == 0:
            break
        if len(data_chunk) < 1024:
            stop = True
        print(len(data_chunk))
        # Append the received data to the overall received_data
        received_data += data_chunk
    error, encrypted_https_request = received_data.split(' ')
    print("")
    encrypted_https_request = bytes.fromhex(encrypted_https_request)

    proxy.send_application_data(encrypted_https_request)
    record, content = proxy.receive_application_data()  
    print("")
    final_response = record.hex() + '|' + content.hex()
    message = "receive_application_data" + space + final_response + space + client_pub_key.hex()
    client.send_data(message.encode())   
    
    received_data = ""
    stop = False
    while True and not stop:
        data_chunk = client.recv_data()
        print("")
        # If the received data is empty, it means the client has finished sending data
        if len(data_chunk) == 0:
            break
        if len(data_chunk) < 1024:
            stop = True
        print(len(data_chunk))
        # Append the received data to the overall received_data
        received_data += data_chunk
           
    error, response = received_data.split(' ')
    print("")
    message = "attest" + space + "None" + space + client_pub_key.hex()
    client.send_data(message.encode())
    received_data = ""
    stop = False
    while True and not stop:
        data_chunk = client.recv_data()
        print("")
        # If the received data is empty, it means the client has finished sending data
        if len(data_chunk) == 0:
            break
        if len(data_chunk) < 1024:
            stop = True
        print(len(data_chunk))
        # Append the received data to the overall received_data
        received_data += data_chunk
    error, attestation_doc_b64 = received_data.split(' ')
    print("")
    attestation_doc = base64.b64decode(attestation_doc_b64)
    print(attestation_doc)
    
    # Get the root cert PEM content
    with open('root.pem', 'r') as file:
        root_cert_pem = file.read()
    
    
    # Get PCR0 from command line parameter
    pcr0 = args.pcr0
    print(pcr0)
    
    error, cypertext = client.recv_data().split(' ')
    print("")
    print(cypertext)

    try:
        verify_attestation_doc(attestation_doc, pcrs = [pcr0], root_cert_pem = root_cert_pem)
        print("attested the certificate")
    except Exception as e:
        print("error:", str(e))

    received_data = ""
    stop = False
    
    while True and not stop:
        data_chunk = client.recv_data()
        print("")
        # If the received data is empty, it means the client has finished sending data
        if data_chunk is None or len(data_chunk) == 0:
            break
        if len(data_chunk) < 1024:
            stop = True
        print(len(data_chunk))
        # Append the received data to the overall received_data
        received_data += data_chunk
    error, attestation_doc_b64_encrypted = received_data.split(' ')
    print("")
    print(attestation_doc_b64_encrypted)
    client.decrypt_data(attestation_doc_b64_encrypted, full_dh_key)
    
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
    parser.add_argument("pcr0", type=str, help="The PCR of the enclave")

    args = parser.parse_args()

    client_handler(args)

if __name__ == "__main__":
    main()
