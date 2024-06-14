import asyncio
import sys
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
import cbor2
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from dotenv import load_dotenv

load_dotenv()

client_private_key = None
shared_key = None
#PCR2 can be precalculated or calculated later when internet connection restores
pcr2 = os.getenv('PCR2')

def read_file(filename):
    with open(filename , "r") as f:
        return f.read()
    
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
    ec2_ip = os.getenv('IP_ADDRESS')
    uri = f"ws://{ec2_ip}:8080"
    async with websockets.connect(uri) as websocket:
        print("[INFO] Connected to the server")

        start_time = time.time()
        
        # Client side key generation
        client_pub_key = generate_dh_key().hex()
        await websocket.send(json.dumps(["generate_dh_key", client_pub_key]))
        response = json.loads(await websocket.recv())
        print(f"[INFO] Server response (DH key generation): {response}")

        if response.get("status") == "success" and response.get("key") == "server_public_key":
            server_pub_key = bytes.fromhex(response["data"])
            # Calculate the shared key for encryption/decryption
            generate_full_dh_key(server_pub_key)
            
            await websocket.send(json.dumps(["attest", "None"]))
            response = json.loads(await websocket.recv())
            print(f"[INFO] Server response (attestation): {response}")

            if response.get("status") == "success" and response.get("key") == "attest":
                attestation_doc_b64 = decrypt_data(response["data"], shared_key, True)
                
                # Received the attestation document from the TEE
                attestation_doc = base64.b64decode(attestation_doc_b64)
                print("[INFO] Attestation document received")

                data = cbor2.loads(attestation_doc)
                # Load and decode document payload
                doc = data[2]
                doc_obj = cbor2.loads(doc)
                pcrs = doc_obj['pcrs']
                
                if pcrs[2].hex() != pcr2:
                    # PCR2 is a hash of the TEE-running code
                    # 1. The client can either precalculate it
                    # 2. Calculate on the spot with locally installed nitro-cli
                    # 3. Do the check afterwards the communication is done to check whether the caller was legit
                    # For the demonstration, we are going with option 1 which is hardcoded in the script
                    print(f"[ERROR] Server is not running the expected code")
                    sys.exit(0)
                
                pcr0 = pcrs[0].hex()
                print(f"[INFO] PCR0: {pcr0}")
                if pcr0.strip('0') == '':
                    # PCR0 being all zeros imply that the Nitro Enclave is running on debug mode (not secure enough)
                    print(f"[ERROR] Enclave running on debug mode!")
                    sys.exit(0)
            
                with open('root.pem', 'r') as file:
                    root_cert_pem = file.read()

                # Verify the legitamicy of the attestation document 
                try:
                    verify_attestation_doc(attestation_doc, pcrs=[pcr0], root_cert_pem=root_cert_pem)
                    print("[INFO] Attestation successful")
                except Exception as e:
                    print(f"[ERROR] Attestation failed: {e}")
                    sys.exit(0)
                
                # Extract public key of the attestation document
                public_key_byte = doc_obj['public_key']
                public_key = RSA.import_key(public_key_byte)

                # secret = shared_key + some_random_message
                shared_key_str = shared_key.hex()
                secret = shared_key_str + "_THIS IS A RANDOM MESSAGE"
                
                # Encrypt the plaintext secret with the public key of the attestation document
                cipher = PKCS1_OAEP.new(public_key)
                ciphertext = cipher.encrypt(str.encode(secret))
                ciphertext_b64 = base64.b64encode(ciphertext).decode()
                print(f"[INFO] Ciphertext in Base64: {ciphertext_b64}")
                
                # Then encrypt the resulting cipher text with the shared key
                encrypted_secret = encrypt_data(ciphertext_b64, shared_key)
                
                # The sent text is basically our secret double encrypted.
                # First by the public key of the attestation document
                # Second by the shared key
                await websocket.send(json.dumps(["secret_decryption", encrypted_secret.hex()]))
                response = json.loads(await websocket.recv())
                print(f"[INFO] Server response (secret decryption): {response}")

                if response.get("status") == "success" and response.get("key") == "secret_decryption":
                    # response["data"] = the secret we sent decrypted by the TEE and re-encrypted with the shared key
                    actual_secret = decrypt_data(response["data"], shared_key, True)
                    if actual_secret == secret:
                        print(f"[INFO] Server successfully decrypted the secret")
                    else:
                        print(f"[ERROR] Server is not running the expected code")
                        sys.exit(0)
                
                # Server is legit. We can send the data with confidence     
                
                # Email body (encrypted with shared key)
                length = int(os.getenv('LENGTH'))
                sent_data = read_file('data.txt')[:length]
                encrypted_content = encrypt_data(sent_data, shared_key)
                await websocket.send(json.dumps(["receive_data", encrypted_content.hex()]))
                response = json.loads(await websocket.recv())
                print(f"[INFO] Server response (receive data): {response}")

                if response.get("status") == "success" and response.get("key") == "receive_data":
                    # Credentials (encrypted with shared key)
                    # client email | AWS SES id token | AWS SES access token | receiver email
                    encrypted_credentials = encrypt_data("bhanukadolphin@gmail.com|AKIAUET47FSVJDPSNS6K|8QmJcpkHSzK5DJbkDcKmAFWtj/VY9FKxpwxo/91Q|bhanukarc@gmail.com", shared_key)
                    await websocket.send(json.dumps(["credentials", encrypted_credentials.hex()]))
                    response = json.loads(await websocket.recv())
                    print(f"[INFO] Server response (credentials): {response}")

                    if response.get("status") == "success" and response.get("key") == "credentials":
                        
                        # Initiate the email sending
                        await websocket.send(json.dumps(["client_hello", "None"]))
                        response = json.loads(await websocket.recv())
                        print(f"[INFO] Server response (client hello): {response}")

                        if response.get("status") == "success" and response.get("key") == "email_response":
                            # The HTTP response send by the email server (ex: Gmail) but encrypted with the shared key
                            actual_response = decrypt_data(response["data"], shared_key, True)
                            actual_response = base64.b64decode(bytes.fromhex(actual_response))
                            print("[INFO] Email response received")

                            # Check the status of the email
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
    num_runs = int(os.getenv('ROUNDS'))

    for _ in range(num_runs):
        elapsed_time = await perform_task()
        total_time += elapsed_time

    average_time = total_time / num_runs
    print(f"[INFO] Average elapsed time over {num_runs} runs: {average_time} seconds")

if __name__ == "__main__":
    asyncio.run(main())
