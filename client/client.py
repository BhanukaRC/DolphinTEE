import asyncio
import websockets
import zlib
import base64
import os
from coincurve import PrivateKey, PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import signature_algorithms
import extensions

client_private_key = None  # Store client's private key globally

async def generate_dh_key():
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

async def receive_server_key(websocket):
    server_key = await websocket.recv()
    return server_key

async def generate_full_dh_key(server_key):
    private_key_obj = PrivateKey(client_private_key)
    peer_public_key_obj = PublicKey(server_key)
    shared_key = private_key_obj.ecdh(peer_public_key_obj.public_key)
    print(shared_key)
    return shared_key

async def encrypt_data(data, dh_key):
    key = dh_key # Convert DH key to bytes
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return iv + ciphertext


async def communicate_with_server():
    async with websockets.connect("ws://localhost:8765") as websocket:
        # Step 1: Generate DH key (client part)

        client_pub_key = await generate_dh_key()

        print("Generated Client Public/Private Keys")

        await websocket.send(client_pub_key)
        
        print("Sent Client Public Key To Server")

        # Step 2: Receive DH key part of the server
        server_pub_key = await receive_server_key(websocket)

        print("Received Server Public Key")

        # Step 3: Generate the full DH key
        full_dh_key = await generate_full_dh_key(server_pub_key)
        
        print("Shared Key", full_dh_key)

        # Step 4: Prepare data and encrypt it based on the DH key
        data_to_send = "Hello, Server!"
        encrypted_data = await encrypt_data(data_to_send, full_dh_key)
        
        # Send encrypted data to the server
        await websocket.send(encrypted_data)
        print(f"Sent encrypted data to server: {encrypted_data}")

asyncio.get_event_loop().run_until_complete(communicate_with_server())
