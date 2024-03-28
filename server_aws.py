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

#import boto3
#from botocore.exceptions import ClientError

# Global dictionaries to store DH keys and content associated with each client key
dh_key_store = {}
content_store = {}

# BODY_HTML = """<html>
# <head></head>
# <body>
#  <h1>DOLPHIN AWS NITRO TEST</h1>
#  <p>This email was sent with
#    <a href='https://aws.amazon.com/ses/'>Amazon SES</a> using the
#    <a href='https://aws.amazon.com/sdk-for-python/'>
#      AWS SDK for Python (Boto)</a>.</p>
# </body>
# </html>
#            """

# CHARSET = "UTF-8"
# AWS_REGION = "us-east-1"


def server_handler(args):
    global dh_key_store
    global content_store

    # Listen for data and return the reverse string of it
    server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    server.bind((socket.VMADDR_CID_ANY, args.port))
    server.listen(1024)
    
    (conn, (remote_cid, remote_port)) = server.accept()
    while True:
        try:
            incoming = conn.recv(1024).decode()
            data_type, content, client_key = None, None, None
            if (len(incoming) > 0):
                data_type, content, client_key = incoming.split(" ")
                print(data_type, content, client_key)
            if data_type == "generate":
                if client_key not in dh_key_store or dh_key_store[client_key] is None:
                    print("[+] Generating ECDH public part...")
                    private_key = PrivateKey.from_hex(os.urandom(32).hex())
                    pub_key = private_key.public_key.format()
                    print(pub_key)
                    sendable_data = pub_key + zlib.crc32(pub_key).to_bytes(4, byteorder='big')
                    b64_data = base64.b64encode(sendable_data)
                    print(f"[+] Public part {sendable_data.hex()} Length : {len(b64_data)}")
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
                    print(shared_key)
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
                    current = content_store[client_key]
                    current += plaintext
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
                    print(plaintext)
                    credentials = plaintext.split('|')
                    sender_email, sender_username, sender_password, receiver_emails = credentials[0], credentials[1], credentials[2], credentials[3]
                    print(sender_email, sender_username, sender_password, receiver_emails)
                    content = content_store[client_key]
                    


                    
                    """
                    email_client = boto3.client('ses',region_name=AWS_REGION,aws_access_key_id=sender_username, aws_secret_access_key=sender_password)

                    # Try to send the email.
                    try:
                        #Provide the contents of the email.
                        response = email_client.send_email(
                            Destination={
                                'ToAddresses': receiver_emails.split(','),
                            },
                            Message={
                                'Body': {
                                    'Html': {
                                        'Charset': CHARSET,
                                        'Data': BODY_HTML,
                                    },
                                    'Text': {
                                        'Charset': CHARSET,
                                        'Data': content,
                                    },
                                },
                                'Subject': {
                                    'Charset': CHARSET,
                                    'Data': "Dolphins are communicating!",
                                },
                            },
                            Source=sender_email,
                        )
                    except ClientError as e:
                        print(e.response['Error']['Message'])
                    else:
                        print("Email sent! Message ID:"),
                        print(response['MessageId'])

                    """

                    output = [False, None]
                    conn.sendall(" ".join(map(str, output)).encode())

        except socket.error as e:
            break
    conn.close()
    server.close()

def main():
    parser = argparse.ArgumentParser(prog='server')
    parser.add_argument("port", type=int, help="The local port to listen on.")

    args = parser.parse_args()
    print("Starting server on port %d" % args.port)
    server_handler(args)
    print("Exiting server")

if __name__ == "__main__":
    main()
