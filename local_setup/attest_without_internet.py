import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from attestation_verifier import verify_attestation_doc
import os

# Run the code in a device without internet connectivity for validating the local attestation capabilities
# The check_local_attestation.sh handles the task of cutting off internet

# Hardcoded values (replace with your actual values)
# These values can be copied from the console when running ws_local_client.py
pcr0 = "f0c1414f2658779a58a4e045ed35e98771b14eca491fad2a9366f2cea403756aa083d2d4cbe6773d25e02f4be99dfd85"
attestation_doc_b64 = (
    "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"
)
root_cert_path = 'root.pem'

from dotenv import load_dotenv

load_dotenv()

def custom_print(*args, **kwargs):
    if os.getenv('ENABLE_PRINTS') == 'True':
        print(*args, **kwargs)
        
def main():
    attestation_doc = base64.b64decode(attestation_doc_b64)
    custom_print("[INFO] Attestation document received")

    # Load the root certificate
    with open(root_cert_path, 'r') as file:
        root_cert_pem = file.read()

    # Verify the attestation document
    try:
        verify_attestation_doc(attestation_doc, pcrs=[pcr0], root_cert_pem=root_cert_pem)
        custom_print("[INFO] Attestation successful")
    except Exception as e:
        custom_print(f"[ERROR] Attestation failed: {e}")
        raise e

if __name__ == "__main__":
    main()
