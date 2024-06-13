import asyncio
import websockets
import json
import os
import zlib
import base64
from coincurve import PrivateKey, PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from attestation_verifier import verify_attestation_doc
import time

client_private_key = None
shared_key = None
pcr0 = None

def generate_dh_key():
    global client_private_key
    print("[INFO] Generating ECDH public key...")
    private_key = PrivateKey.from_hex(os.urandom(32).hex())
    pub_key = private_key.public_key.format()
    sendable_data = pub_key + zlib.crc32(pub_key).to_bytes(4, byteorder='big')
    b64_data = base64.b64encode(sendable_data)
    print(f"[INFO] Public key generated: {sendable_data.hex()} (Length: {len(b64_data)})")
    client_private_key = private_key.secret
    return pub_key

def generate_full_dh_key(server_key):
    private_key_obj = PrivateKey(client_private_key)
    peer_public_key_obj = PublicKey(server_key)
    global shared_key
    shared_key = private_key_obj.ecdh(peer_public_key_obj.public_key)
    print("[INFO] Shared key established")
    return shared_key

def encrypt_data(data, dh_key):
    key = dh_key
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return iv + ciphertext

def decrypt_data(content, shared_key, b64_encoded=False):
    content = bytes.fromhex(content)
    iv = content[:16]
    ciphertext = content[16:]
    cipher = Cipher(algorithms.AES(shared_key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

async def perform_task():
    uri = "ws://54.165.67.63:8080"
    async with websockets.connect(uri) as websocket:
        print("[INFO] Connected to the server")

        start_time = time.time()
        
        client_pub_key = generate_dh_key().hex()
        await websocket.send(json.dumps(["generate_dh_key", client_pub_key]))
        response = json.loads(await websocket.recv())
        print(f"[INFO] Server response (DH key generation): {response}")

        if response.get("status") == "success" and response.get("key") == "server_public_key":
            server_pub_key = bytes.fromhex(response["data"])
            generate_full_dh_key(server_pub_key)
            
            await websocket.send(json.dumps(["pcr", "None"]))
            response = json.loads(await websocket.recv())
            print(f"[INFO] Server response (PCR0): {response}")
            global pcr0
            pcr0 = response["data"]
            
            await websocket.send(json.dumps(["attest", "None"]))
            response = json.loads(await websocket.recv())
            print(f"[INFO] Server response (attestation): {response}")

            if response.get("status") == "success" and response.get("key") == "attest":
                attestation_doc_b64 = response["data"]
                attestation_doc = base64.b64decode(attestation_doc_b64)
                print("[INFO] Attestation document received")

                with open('root.pem', 'r') as file:
                    root_cert_pem = file.read()

                try:
                    verify_attestation_doc(attestation_doc, pcrs=[pcr0], root_cert_pem=root_cert_pem)
                    print("[INFO] Attestation successful")
                except Exception as e:
                    print(f"[ERROR] Attestation failed: {e}")
                    raise e

                encrypted_content = encrypt_data("Hello from client", shared_key)
                await websocket.send(json.dumps(["receive_data", encrypted_content.hex()]))
                response = json.loads(await websocket.recv())
                print(f"[INFO] Server response (receive data): {response}")

                if response.get("status") == "success" and response.get("key") == "receive_data":
                    encrypted_credentials = encrypt_data("bhanukadolphin@gmail.com|AKIAUET47FSVJDPSNS6K|8QmJcpkHSzK5DJbkDcKmAFWtj/VY9FKxpwxo/91Q|bhanukarc@gmail.com", shared_key)
                    await websocket.send(json.dumps(["credentials", encrypted_credentials.hex()]))
                    response = json.loads(await websocket.recv())
                    print(f"[INFO] Server response (credentials): {response}")

                    if response.get("status") == "success" and response.get("key") == "credentials":
                        await websocket.send(json.dumps(["client_hello", "None"]))
                        response = json.loads(await websocket.recv())
                        print(f"[INFO] Server response (client hello): {response}")

                        if response.get("status") == "success" and response.get("key") == "email_response":
                            actual_response = decrypt_data(response["data"], shared_key, True)
                            actual_response = base64.b64decode(bytes.fromhex(actual_response))
                            print("[INFO] Email response received")

                            response_str = actual_response.decode('utf-8')
                            if "HTTP/1.1 200 OK" in response_str:
                                print("[INFO] Status is 200")
                            else:
                                print("[INFO] Status is not 200")
                            
                            end_time = time.time()
                            elapsed_time = end_time - start_time
                            print(f"[INFO] Elapsed time: {elapsed_time} seconds")
                            return elapsed_time

async def main():
    total_time = 0
    num_runs = 10

    for _ in range(num_runs):
        elapsed_time = await perform_task()
        total_time += elapsed_time

    average_time = total_time / num_runs
    print(f"[INFO] Average elapsed time over {num_runs} runs: {average_time} seconds")

if __name__ == "__main__":
    asyncio.run(main())
