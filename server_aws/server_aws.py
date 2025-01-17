#!/usr/local/bin/python3

# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Dict
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
from tls_client import Client
import cbor2
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from NsmUtil import NSMUtil
from dotenv import load_dotenv

load_dotenv()

# Global dictionaries to store DH keys and content associated with each client key
dh_key_store = {}
content_store = {}
credentials_store = {}
nsm_util_store = {}
tls_connection_object_store: Dict[str, Client] = {}

def custom_print(*args, **kwargs):
    if os.getenv('ENABLE_PRINTS') == 'True':
        print(*args, **kwargs)
        
def encrypt_data_for_client(data, dh_key):
    key = dh_key  # Convert DH key to bytes
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return iv + ciphertext

def encrypt(attestation_doc, plaintext):
    """
    Encrypt message using public key in attestation document
    """

    # Decode CBOR attestation document
    data = cbor2.loads(attestation_doc)

    # Load and decode document payload
    doc = data[2]
    doc_obj = cbor2.loads(doc)

    # Get the public key from attestation document
    public_key_byte = doc_obj['public_key']
    public_key = RSA.import_key(public_key_byte)

    # Encrypt the plaintext with the public key and encode the cipher text in base64
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(str.encode(plaintext))

    return base64.b64encode(ciphertext).decode()

def server_handler(args):
    global dh_key_store
    global content_store
    global nsm_util_store
    
    # Listen for data and return the reverse string of it
    server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    server.bind((socket.VMADDR_CID_ANY, args.port))
    server.listen(1024)
    
    custom_print(f"[INFO] Server listening on port {args.port}")

    (conn, (remote_cid, remote_port)) = server.accept()
    custom_print(f"[INFO] Connection accepted from CID {remote_cid}, port {remote_port}")

    incoming = ''
    while True:
        try:
            incoming = incoming if len(incoming) > 0 else conn.recv(1024).decode()
            data_type, content, client_key = None, None, None
            if len(incoming) > 0:
                data_type, content, client_key = incoming.split(" ")
                custom_print(f"[INFO] Received - Type: {data_type}, Content: {content}, Client Key: {client_key}")
                incoming = ''
            if data_type == "generate":
                if client_key not in dh_key_store or dh_key_store[client_key] is None:
                    custom_print("[INFO] Generating ECDH public part...")
                    private_key = PrivateKey.from_hex(os.urandom(32).hex())
                    pub_key = private_key.public_key.format()
                    custom_print(f"[INFO] Public key: {pub_key.hex()}")
                    sendable_data = pub_key + zlib.crc32(pub_key).to_bytes(4, byteorder='big')
                    b64_data = base64.b64encode(sendable_data)
                    custom_print(f"[INFO] Public part {sendable_data.hex()} Length: {len(b64_data)}")
                    server_private_key = private_key.secret
                    dh_key_store[client_key] = [server_private_key, None]
                    output = [False, pub_key.hex()]
                    conn.sendall(" ".join(map(str, output)).encode())
                else:
                    output = [True, "Already Calculated DH Server Public Key"]
                    conn.sendall(" ".join(map(str, output)).encode())
            elif data_type == "calculate":
                if client_key not in dh_key_store or dh_key_store[client_key] is None:
                    output = [True, "Invalid DH Client Public Key"]
                    conn.sendall(" ".join(map(str, output)).encode())
                elif dh_key_store[client_key][1] is not None:
                    output = [True, "Already Calculated DH Server Shared Key"]
                    conn.sendall(" ".join(map(str, output)).encode())
                else:
                    client_key_in_bytes = bytes.fromhex(client_key)
                    private_key_obj = PrivateKey(dh_key_store[client_key][0])
                    peer_public_key_obj = PublicKey(client_key_in_bytes)
                    shared_key = private_key_obj.ecdh(peer_public_key_obj.public_key)
                    custom_print(f"[INFO] Shared key: {shared_key.hex()}")
                    temp = dh_key_store[client_key]
                    temp[1] = shared_key
                    content_store[client_key] = ''
                    output = [False, None]
                    conn.sendall(" ".join(map(str, output)).encode())
            elif data_type == "decrypt_content":
                if client_key not in dh_key_store or dh_key_store[client_key] is None or dh_key_store[client_key][1] is None:
                    output = [True, "Invalid DH Client Public Key"]
                    conn.sendall(" ".join(map(str, output)).encode())
                else:
                    shared_key = dh_key_store[client_key][1]
                    custom_print(f"[INFO] Shared key: {shared_key.hex()}")
                    content = bytes.fromhex(content)
                    iv = content[:16]  # Extract IV from the beginning of the ciphertext
                    ciphertext = content[16:]  # Extract ciphertext after the IV
                    cipher = Cipher(algorithms.AES(shared_key), modes.CTR(iv), backend=default_backend())
                    decryptor = cipher.decryptor()
                    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                    plaintext = plaintext.decode()
                    custom_print(f"[INFO] Decrypted content: {plaintext}")
                    current = content_store[client_key]
                    current += plaintext
                    content_store[client_key] = current
                    output = [False, None]
                    conn.sendall(" ".join(map(str, output)).encode())
            elif data_type == "credentials":
                if client_key not in dh_key_store or dh_key_store[client_key] is None or dh_key_store[client_key][1] is None:
                    output = [True, "Invalid DH Client Public Key"]
                    conn.sendall(" ".join(map(str, output)).encode())
                else:
                    shared_key = dh_key_store[client_key][1]
                    content = bytes.fromhex(content)
                    iv = content[:16]  # Extract IV from the beginning of the ciphertext
                    ciphertext = content[16:]  # Extract ciphertext after the IV
                    cipher = Cipher(algorithms.AES(shared_key), modes.CTR(iv), backend=default_backend())
                    decryptor = cipher.decryptor()
                    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                    plaintext = plaintext.decode()
                    custom_print(f"[INFO] Credentials: {plaintext}")
                    credentials_store[client_key] = plaintext
                    output = [False, None]
                    conn.sendall(" ".join(map(str, output)).encode())
            elif data_type == "client_hello":
                if client_key not in dh_key_store or dh_key_store[client_key] is None or dh_key_store[client_key][1] is None:
                    output = [True, "Invalid DH Client Public Key"]
                    conn.sendall(" ".join(map(str, output)).encode())
                else:
                    # Client Side of the TLS Connection
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
                        )),
                        extensions.SupportedGroupsExtension((ec_curves.SECP256R1(),)),
                        extensions.SupportedVersionsExtension((tls_version,)),
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

                    client = Client("email.us-east-2.amazonaws.com", port, tls_version, cipher_suites, extensions=exts, match_hostname=True, ssl_key_logfile=ssl_key_logfile)
                    tls_connection_object_store[client_key] = client
                    client_hello = client.client_hello()
                    output = [False, client_hello.hex()]
                    conn.sendall(" ".join(map(str, output)).encode())
            elif data_type == "server_hello":
                # data from server hello
                if client_key not in dh_key_store or dh_key_store[client_key] is None or dh_key_store[client_key][1] is None:
                    output = [True, "Invalid DH Client Public Key"]
                    conn.sendall(" ".join(map(str, output)).encode())
                elif tls_connection_object_store[client_key] is None:
                    output = [True, "TLS Connection Missing"]
                    conn.sendall(" ".join(map(str, output)).encode())
                else:
                    client = tls_connection_object_store[client_key]
                    record_bytes, hello_bytes, certificate_bytes, next_bytes, hello_done_bytes = content.split('|')
                    custom_print(len(bytes.fromhex(record_bytes)))
                    custom_print(len(bytes.fromhex(hello_bytes)))
                    custom_print(len(bytes.fromhex(certificate_bytes)))
                    custom_print(len(bytes.fromhex(next_bytes)))
                    custom_print(len(bytes.fromhex(hello_done_bytes)))
                    client.server_hello(bytes.fromhex(record_bytes), bytes.fromhex(hello_bytes), bytes.fromhex(certificate_bytes), bytes.fromhex(next_bytes), bytes.fromhex(hello_done_bytes))
                    client_finish = client.client_finish()
                    tls_connection_object_store[client_key] = client
                    output = [False, client_finish.hex()]
                    conn.sendall(" ".join(map(str, output)).encode())
            elif data_type == "server_finish":
                # Data from server finish
                if client_key not in dh_key_store or dh_key_store[client_key] is None or dh_key_store[client_key][1] is None:
                    output = [True, "Invalid DH Client Public Key"]
                    conn.sendall(" ".join(map(str, output)).encode())
                elif tls_connection_object_store[client_key] is None:
                    output = [True, "TLS Connection Missing"]
                    conn.sendall(" ".join(map(str, output)).encode())
                else:
                    client = tls_connection_object_store[client_key]
                    record, content = content.split("|")
                    client.server_finish(bytes.fromhex(record), bytes.fromhex(content))
                    plaintext = credentials_store[client_key]
                    credentials = plaintext.split('|')
                    sender_email, sender_username, sender_password, receiver_email = credentials[0], credentials[1], credentials[2], credentials[3]
                    custom_print(f"[INFO] Sender Email: {sender_email}, Username: {sender_username}, Password: {sender_password}, Receiver Email: {receiver_email}")
                    content = content_store[client_key]
                    custom_print(f"[INFO] Content: {content}")
                    encrypted_https_request = client.send_application_data(sender_email, sender_username, sender_password, receiver_email, content)
                    tls_connection_object_store[client_key] = client
                    output = [False, encrypted_https_request.hex()]
                    conn.sendall(" ".join(map(str, output)).encode())
            elif data_type == "receive_application_data":
                # Response from the server for the HTTPS request
                if client_key not in dh_key_store or dh_key_store[client_key] is None or dh_key_store[client_key][1] is None:
                    output = [True, "Invalid DH Client Public Key"]
                    conn.sendall(" ".join(map(str, output)).encode())
                elif tls_connection_object_store[client_key] is None:
                    output = [True, "TLS Connection Missing"]
                    conn.sendall(" ".join(map(str, output)).encode())
                else:
                    client = tls_connection_object_store[client_key]
                    record, content = content.split("|")
                    decrypted_result = client.receive_application_data(bytes.fromhex(record), bytes.fromhex(content))
                    custom_print(f"[INFO] Decrypted result: {decrypted_result}")
                    decrypted_result = base64.b64encode(decrypted_result)
                    custom_print(f"[INFO] Base64-encoded decrypted result: {decrypted_result}")
                    decrypted_result = decrypted_result.hex()
                    shared_key = dh_key_store[client_key][1]
                    encrypted_response = encrypt_data_for_client(decrypted_result, shared_key)
                    output = [False, encrypted_response.hex()]
                    conn.sendall(" ".join(map(str, output)).encode())

            elif data_type == "attest":
                if client_key not in dh_key_store or dh_key_store[client_key] is None or dh_key_store[client_key][1] is None:
                    output = [True, "Invalid DH Client Public Key"]
                    conn.sendall(" ".join(map(str, output)).encode())
                else:
                    # Initialise NSMUtil
                    nsm_util = NSMUtil()
                    attestation_doc = nsm_util.get_attestation_doc()
                    nsm_util_store[client_key] = nsm_util
                    custom_print(f"[INFO] Attestation document: {attestation_doc}")
                    # Base64 encode the attestation doc
                    attestation_doc_b64 = base64.b64encode(attestation_doc).decode()
                    
                    shared_key = dh_key_store[client_key][1]
                    shared_key_str = shared_key.hex()
                    secret = shared_key_str + "_THIS IS A SECURED MESSAGE"
                    ciphertext_b64 = encrypt(attestation_doc, secret)
                    ciphertext = base64.b64decode(ciphertext_b64)
                    plaintext = nsm_util.decrypt(ciphertext)
                    custom_print(f"[INFO] Plaintext: {plaintext}, Ciphertext (Base64): {ciphertext_b64}, Secret: {secret}")
                    if plaintext == secret:
                        custom_print("[INFO] Encryption and decryption works!")
                    
                    attestation_doc_encrypted = encrypt_data_for_client(attestation_doc_b64, shared_key)
                    
                    custom_print(f"[INFO] Attestation document encrypted: {attestation_doc_encrypted.hex()}")
                    output = [False, attestation_doc_encrypted.hex()]
                    conn.sendall(" ".join(map(str, output)).encode())
                    
            elif data_type == "secret_decryption":
                if client_key not in dh_key_store or dh_key_store[client_key] is None or dh_key_store[client_key][1] is None:
                    output = [True, "Invalid DH Client Public Key"]
                    conn.sendall(" ".join(map(str, output)).encode())
                else:
                    shared_key = dh_key_store[client_key][1]
                    content = bytes.fromhex(content)
                    iv = content[:16]  # Extract IV from the beginning of the ciphertext
                    ciphertext = content[16:]  # Extract ciphertext after the IV
                    cipher = Cipher(algorithms.AES(shared_key), modes.CTR(iv), backend=default_backend())
                    decryptor = cipher.decryptor()
                    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                    # secret encrypted with attestation doc public key
                    ciphertext_b64 = plaintext.decode()
                    
                    nsm_util = nsm_util_store[client_key]
                    ciphertext = base64.b64decode(ciphertext_b64)
                    actual_secret = nsm_util.decrypt(ciphertext)
                    custom_print(f"[INFO] Plaintext: {actual_secret}, Ciphertext (Base64): {ciphertext_b64}")
                    
                    secret_reencrypted = encrypt_data_for_client(actual_secret, shared_key)
                    
                    custom_print(f"[INFO] Decrypted and re-encrypted secret: {secret_reencrypted.hex()}")
                    output = [False, secret_reencrypted.hex()]
                    conn.sendall(" ".join(map(str, output)).encode())
                    
                    #conn.close()
                    #server.close()
        except ValueError:
            custom_print("[ERROR] ValueError encountered, likely due to incomplete data. Continuing to receive more data.")
            # If split fails due to incomplete data, keep receiving until complete
            while True and len(incoming) > 0:
                more_data = conn.recv(1024).decode()
                if not more_data:
                    break
                incoming += more_data
                try:
                    data_type, content, client_key = incoming.split(" ")
                    custom_print(f"[INFO] Successfully received complete data - Type: {data_type}, Content: {content}, Client Key: {client_key}")
                    break  # Exit the loop if split succeeds
                except ValueError:
                    custom_print("[INFO] Incomplete data received, waiting for more data...")
                    pass  # Continue receiving until a complete message is received
        except socket.error as e:
            break
    conn.close()
    server.close()

def main():
    parser = argparse.ArgumentParser(prog='server')
    parser.add_argument("port", type=int, help="The local port to listen on.")

    args = parser.parse_args()
    custom_print(f"[INFO] Starting server on port {args.port}")
    server_handler(args)
    custom_print("[INFO] Exiting server")

if __name__ == "__main__":
    main()
