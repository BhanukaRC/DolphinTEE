import asyncio
import websockets
import zlib
import base64
import os
from coincurve import PrivateKey, PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

server_private_key = None  # Store server's private key globally

async def generate_dh_key():
    global server_private_key
    print("[+] Generating ECDH public part...")
    private_key = PrivateKey.from_hex(os.urandom(32).hex())
    pub_key = private_key.public_key.format()
    print(pub_key)
    sendable_data = pub_key + zlib.crc32(pub_key).to_bytes(4, byteorder='big')
    b64_data = base64.b64encode(sendable_data)
    print(f"[+] Public part {sendable_data.hex()} Length : {len(b64_data)}")
    server_private_key = private_key.secret
    return pub_key

async def receive_client_key(websocket):
    client_key = await websocket.recv()
    return client_key

async def generate_full_dh_key(client_key):
    private_key_obj = PrivateKey(server_private_key)
    peer_public_key_obj = PublicKey(client_key)
    shared_key = private_key_obj.ecdh(peer_public_key_obj.public_key)
    print(shared_key)
    return shared_key

async def decrypt_data(data, dh_key):
    #key = dh_key.to_bytes(32, byteorder='big')  # Convert DH key to bytes
    key = dh_key
    iv = data[:16]  # Extract IV from the beginning of the ciphertext
    ciphertext = data[16:]  # Extract ciphertext after the IV
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

async def handle_client(websocket, path):
    # Step 1: Receive DH key part of the client
    client_pub_key = await receive_client_key(websocket)
    print("Received Client Public Key")

    # Step 2: Generate DH key (server part)
    server_pub_key = await generate_dh_key()

    print("Generated Server Public/Private Keys")

    await websocket.send(server_pub_key)

    print("Sent Server Public Key To Client")
    
    # Step 3: Generate the full DH key
    full_dh_key = await generate_full_dh_key(client_pub_key)
    
    print("Shared Key", full_dh_key)

    # Step 4: Receive encrypted data and decrypt it based on the DH key
    encrypted_data = await websocket.recv()
    print("Encrypted Data", encrypted_data)

    decrypted_data = await decrypt_data(encrypted_data, full_dh_key)
    
    print(f"Received and decrypted data: {decrypted_data}")

start_server = websockets.serve(handle_client, "localhost", 8765)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
