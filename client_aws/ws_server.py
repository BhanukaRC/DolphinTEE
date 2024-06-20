import argparse
import asyncio
import websockets
import json
import socket
import zlib
import base64
import os
from coincurve import PrivateKey, PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Import your existing modules
import extensions
import ec_curves
import signature_algorithms
import constants
import tls
from tls_proxy import Proxy

from dotenv import load_dotenv

load_dotenv()

def custom_print(*args, **kwargs):
    if os.getenv('ENABLE_PRINTS') == 'True':
        print(*args, **kwargs)
        
class VsockStream:
    def __init__(self, conn_tmo=5):
        self.conn_tmo = conn_tmo
        self.sock = None
        self.client_pub_key = None

    def connect(self, endpoint):
        """Connect to the remote endpoint"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.settimeout(self.conn_tmo)
        self.sock.connect(endpoint)
        custom_print(f"[INFO] Connected to endpoint {endpoint}")

    def send_data(self, data):
        """Send data to a remote endpoint"""
        self.sock.sendall(data)
        custom_print(f"[INFO] Sent data to the TEE: {data}")

    def recv_data(self):
        """Receive data from a remote endpoint"""
        while True:
            data = self.sock.recv(1024).decode()
            if not data:
                break
            #custom_print(data, end='', flush=True)
            return data
        custom_print()

    def disconnect(self):
        """Close the client socket"""
        self.sock.close()
        custom_print("[INFO] Disconnected from the endpoint")

    async def handle_action(self, websocket, path):
        space = " "
        none = "None"
        async for message in websocket:
            custom_print(f"[INFO] Received message from WebSocket: {message}")
            data = json.loads(message)
            if isinstance(data, list) and len(data) > 0:
                action = data[0]
                content = data[1]

                if action == "generate_dh_key":
                    self.client_pub_key = content
                    custom_print(f"[INFO] Client public key: {self.client_pub_key}")

                    # Initiate key generation at the Enclave
                    message = f"generate{space}{none}{space}{self.client_pub_key}"
                    self.send_data(message.encode())
                    error, server_pub_key = self.recv_data().split(' ')
                    custom_print(f"[INFO] Server public key: {server_pub_key}")

                    message = f"calculate{space}{none}{space}{self.client_pub_key}"
                    self.send_data(message.encode())
                    error, response = self.recv_data().split(' ')
                    custom_print(f"[INFO] Server calculated the shared key")
                    response = {"status": "success", "key": "server_public_key", "data": server_pub_key}

                elif action == "attest":
                    # Request for the attestation document
                    message = f"attest{space}{none}{space}{self.client_pub_key}"
                    self.send_data(message.encode())
                    received_data = ""
                    stop = False
                    while True and not stop:
                        data_chunk = self.recv_data()
                        #custom_print("")
                        # If the received data is empty, it means the client has finished sending data
                        if len(data_chunk) == 0:
                            break
                        if len(data_chunk) < 1024:
                            stop = True
                        #custom_print(len(data_chunk))
                        # Append the received data to the overall received_data
                        received_data += data_chunk

                    
                    error, attestation_doc_b64_encrypted = received_data.split(' ')
                    custom_print(f"[INFO] Encrypted Attestation document received")
                    
                    response = {"status": "success", "key": "attest", "data": attestation_doc_b64_encrypted}

                elif action == "secret_decryption":
                    encrypted_secret = content

                    # Pass the encrypted secret to the Enclave
                    message = f"secret_decryption{space}{encrypted_secret}{space}{self.client_pub_key}"
                    self.send_data(message.encode())
                    error, response = self.recv_data().split(' ')
                    custom_print(f"[INFO] Server decrypted the secret")
                    response = {"status": "success", "key": "secret_decryption", "data": response}
                    
                elif action == "receive_data":
                    encrypted_data = content

                    # Pass the encrypted data to the Enclave
                    message = f"decrypt_content{space}{encrypted_data}{space}{self.client_pub_key}"
                    self.send_data(message.encode())
                    error, response = self.recv_data().split(' ')
                    custom_print(f"[INFO] Server received the content")
                    response = {"status": "success", "key": "receive_data"}

                elif action == "credentials":
                    encrypted_data = content

                    # Pass the encrypted credentials to the Enclave
                    message = f"credentials{space}{encrypted_data}{space}{self.client_pub_key}"
                    self.send_data(message.encode())
                    error, response = self.recv_data().split(' ')
                    custom_print(f"[INFO] Server received the credentials")
                    response = {"status": "success", "key": "credentials"}

                elif action == "client_hello":
                    # Initiate TLS key generation at the Enclave
                    message = f"client_hello{space}{none}{space}{self.client_pub_key}"
                    self.send_data(message.encode())
                    error, client_hello = self.recv_data().split(' ')
                    custom_print(f"[INFO] Client hello: {client_hello}")

                    client_hello = bytes.fromhex(client_hello)

                    # Initiate TLS connection
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

                    proxy.client_hello(client_hello)

                    record_bytes, hello_bytes = proxy.server_hello_1()
                    certificate_bytes = proxy.server_hello_2()
                    next_bytes = proxy.server_hello_3()
                    hello_done_bytes = proxy.server_hello_4()

                    custom_print(f"[INFO] Server hello part lengths: {len(record_bytes)}, {len(hello_bytes)}, {len(certificate_bytes)}, {len(next_bytes)}, {len(hello_done_bytes)}")

                    server_hello = f"{record_bytes.hex()}|{hello_bytes.hex()}|{certificate_bytes.hex()}|{next_bytes.hex()}|{hello_done_bytes.hex()}"
                    message = f"server_hello{space}{server_hello}{space}{self.client_pub_key}"
                    self.send_data(message.encode())
                    error, client_finish = self.recv_data().split(' ')
                    custom_print(f"[INFO] Client finish: {client_finish}")
                    client_finish = bytes.fromhex(client_finish)
                    proxy.client_finish(client_finish)
                    record, content = proxy.server_finish()

                    server_finish = f"{record.hex()}|{content.hex()}"
                    message = f"server_finish{space}{server_finish}{space}{self.client_pub_key}"
                    self.send_data(message.encode())

                    received_data = ""
                    stop = False
                    while True and not stop:
                        data_chunk = self.recv_data()
                        #custom_print("")
                        # If the received data is empty, it means the client has finished sending data
                        if len(data_chunk) == 0:
                            break
                        if len(data_chunk) < 1024:
                            stop = True
                        #custom_print(len(data_chunk))
                        # Append the received data to the overall received_data
                        received_data += data_chunk

                    error, encrypted_https_request = received_data.split(' ')
                    custom_print(f"[INFO] Encrypted HTTP request: {encrypted_https_request}")
                    encrypted_https_request = bytes.fromhex(encrypted_https_request)

                    proxy.send_application_data(encrypted_https_request)
                    record, content = proxy.receive_application_data()
                    final_response = f"{record.hex()}|{content.hex()}"
                    custom_print(f"[INFO] TLS Encrypted HTTP response: {final_response}")
                    message = f"receive_application_data{space}{final_response}{space}{self.client_pub_key}"
                    self.send_data(message.encode())

                    received_data = ""
                    stop = False
                    while True and not stop:
                        data_chunk = self.recv_data()
                        #custom_print("")
                        # If the received data is empty, it means the client has finished sending data
                        if len(data_chunk) == 0:
                            break
                        if len(data_chunk) < 1024:
                            stop = True
                        #custom_print(len(data_chunk))
                        # Append the received data to the overall received_data
                        received_data += data_chunk

                    error, encrypted_response = received_data.split(' ')
                    custom_print(f"[INFO] TLS Decrypted but Shared-key Encrypted HTTP response: {encrypted_response}")
                    response = {"status": "success", "data": encrypted_response, "key": "email_response"}
                else:
                    response = {"status": "error", "data": "Unknown action"}
            else:
                response = {"status": "error", "data": "Invalid message format"}
            await websocket.send(json.dumps(response))
            custom_print(f"[INFO] Sent response via WebSocket: {response}")

    async def ws_server(self, port=8080):
        server = await websockets.serve(self.handle_action, "0.0.0.0", port)
        custom_print(f"[INFO] WebSocket server is running on ws://0.0.0.0:{port}")
        await server.wait_closed()

def main():
    parser = argparse.ArgumentParser(prog='client')
    parser.add_argument("server_cid", type=int, help="The CID of the enclave running the server")
    parser.add_argument("server_port", type=int, help="The port of the server")

    args = parser.parse_args()

    client = VsockStream()
    endpoint = (args.server_cid, args.server_port)
    client.connect(endpoint)

    # Run the WebSocket server
    asyncio.run(client.ws_server())

if __name__ == "__main__":
    main()
