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

class VsockStream:
    def __init__(self, conn_tmo=5):
        self.conn_tmo = conn_tmo
        self.sock = None
        self.client_pub_key = None
        self.pcr = None

    def connect(self, endpoint, pcr_val):
        """Connect to the remote endpoint"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.settimeout(self.conn_tmo)
        self.sock.connect(endpoint)
        self.pcr = pcr_val
        
    def send_data(self, data):
        """Send data to a remote endpoint"""
        self.sock.sendall(data)

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

    async def handle_action(self, websocket, path):
        space = " "
        async for message in websocket:
            print(f"Received: {message}")
            data = json.loads(message)  
            if isinstance(data, list) and len(data) > 0:
                action = data[0]
                content = data[1]
                
                if action == "generate_dh_key":
                    self.client_pub_key = data[1]
                    print("client pub key", self.client_pub_key)
                    
                    # Initiate key generation at the Enclave
                    message = "generate" + space + "None" + space + self.client_pub_key
                    self.send_data(message.encode())
                    error, server_pub_key = self.recv_data().split(' ')
                    print("")
                    print(server_pub_key)
                    
                    # Initiate shared key calculation at the Enclave
                    message = "calculate" + space + "None" + space + self.client_pub_key
                    self.send_data(message.encode())
                    error, response = self.recv_data().split(' ')
                    print("")
                    response = {"status": "success", "key": "server_public_key", "data": server_pub_key}
                
                elif action == "pcr":
                    # Send PCR0 to client
                    response = {"status": "success", "key": "pcr", "data": self.pcr}
                    
                elif action == "attest":
                    
                    # Request for the attestation document
                    print("client pub key", self.client_pub_key)
                    
                    message = "attest" + space + "None" + space + self.client_pub_key
                    self.send_data(message.encode())
                    received_data = ""
                    stop = False
                    while True and not stop:
                        data_chunk = self.recv_data()
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
                    
                    error, cypertext = self.recv_data().split(' ')
                    print("")
                    print(cypertext)
                    
                    received_data = ""
                    stop = False
                    while True and not stop:
                        data_chunk = self.recv_data()
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
                    
                    response = {"status": "success", "key": "attest", "data": attestation_doc_b64}
                    
                elif action == "receive_data":
                    encrypted_data = content
                    
                    # Pass the encrypted data to the Enclave
                    message = "decrypt_content" + space + encrypted_data + space + self.client_pub_key
                    self.send_data(message.encode())
                    error, response = self.recv_data().split(' ')
                    print("")
                    response = {"status": "success", "key": "receive_data" }
                
                elif action == "credentials":
                    encrypted_data = content
                    
                    # Pass the encrypted credentials to the Enclave
                    message = "credentials" + space + encrypted_data + space + self.client_pub_key
                    self.send_data(message.encode())
                    error, response = self.recv_data().split(' ')
                    print("")
                    response = {"status": "success", "key": "credentials" }
                        
                elif action == "client_hello":
                    # initiate TLS key generation at the Enclave
                    
                    message = "client_hello" + space + "None" + space + self.client_pub_key
                    self.send_data(message.encode())
                    error, client_hello = self.recv_data().split(' ')
                    print("6")
                    print("client_hello", client_hello)
                    #Error here. may be read again for something not read
                    
                    client_hello = bytes.fromhex(client_hello)
                    
                    # initiate TLS connection
                    
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
                    message = "server_hello" + space + server_hello + space + self.client_pub_key
                    self.send_data(message.encode())
                    error, client_finish = self.recv_data().split(' ')
                    print("")
                    
                    client_finish = bytes.fromhex(client_finish)
                    proxy.client_finish(client_finish)
                    record, content = proxy.server_finish()
                    
                    server_finish = record.hex() + '|' + content.hex()
                    message = "server_finish" + space + server_finish + space + self.client_pub_key
                    self.send_data(message.encode())
                    
                    received_data = ""
                    stop = False
                    while True and not stop:
                        data_chunk = self.recv_data()
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
                    message = "receive_application_data" + space + final_response + space + self.client_pub_key
                    self.send_data(message.encode())

                    received_data = ""
                    stop = False
                    while True and not stop:
                        data_chunk = self.recv_data()
                        print("")
                        # If the received data is empty, it means the client has finished sending data
                        if len(data_chunk) == 0:
                            break
                        if len(data_chunk) < 1024:
                            stop = True
                        print(len(data_chunk))
                        # Append the received data to the overall received_data
                        received_data += data_chunk

                    error, encrypted_response = received_data.split(' ')
                    print(" ")
                    response = {"status": "success", "data": encrypted_response, "key": "email_response"}
                else:
                    response = {"status": "error", "data": "Unknown action"}
            else:
                response = {"status": "error", "data": "Invalid message format"}
            await websocket.send(json.dumps(response))

    async def ws_server(self, port=8080):
        server = await websockets.serve(self.handle_action, "0.0.0.0", port)
        print(f"WebSocket server is running on ws://0.0.0.0:{port}")
        await server.wait_closed()

def main():
    parser = argparse.ArgumentParser(prog='client')
    parser.add_argument("server_cid", type=int, help="The CID of the enclave running the server")
    parser.add_argument("server_port", type=int, help="The port of the server")
    parser.add_argument("pcr0", type=str, help="The PCR of the enclave")

    args = parser.parse_args()

    client = VsockStream()
    endpoint = (args.server_cid, args.server_port)
    client.connect(endpoint, args.pcr0)

    # Run the WebSocket server
    asyncio.run(client.ws_server())

if __name__ == "__main__":
    main()
