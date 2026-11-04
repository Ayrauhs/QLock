#The Decryption Vault
import json
import sys
import ascon
from hardware_binder import HardwareBinder
from laser_alignment_gui import run_alignment_hud
from pqc_engine import MLKEM768Engine

def decrypt_payload(filename="encrypted_payload.json"):
    print("\n==================================================")
    print("   QLOCK: OPTICAL & HARDWARE DECRYPTION VAULT     ")
    print("==================================================")

    if not run_alignment_hud():
        print("\n==================================================")
        print("     OPTICAL SECURITY BREACH       ")
        print("==================================================")
        print("Decryption aborted: Laser beam not locked or user cancelled.\n")
        return None

    try:
        with open(filename, "r") as f:
            payload = json.load(f)

        ciphertext = bytes.fromhex(payload["ciphertext"])
        tag = bytes.fromhex(payload["tag"])
        nonce = bytes.fromhex(payload["nonce"])
        salt = bytes.fromhex(payload["salt"])
        kem_ct = bytes.fromhex(payload["kem_ciphertext"])
        sealed_nonce = bytes.fromhex(payload["sealed_nonce"])
        sealed_keys = bytes.fromhex(payload["sealed_keys"])

        print("Querying Hardware Info and HKDF KEY...")
        # Recover K_BBM92 and the ML-KEM secret key (only opens on the original hardware),
        # then perform a real ML-KEM-768 decapsulation to obtain S_PQC.
        q_key, kem_sk = HardwareBinder.unseal_keys(sealed_keys, salt, sealed_nonce)
        pqc_secret = MLKEM768Engine().decapsulate(kem_ct, kem_sk)
        master_key = HardwareBinder.derive_bound_key(q_key, pqc_secret, salt)

        # Decrypt using Ascon-AEAD lightweight standard (Ascon-128); tag is verified inside
        decrypted_bytes = ascon.decrypt(master_key, nonce, HardwareBinder.payload_aad(kem_ct),
                                        ciphertext + tag, variant="Ascon-128")

        if decrypted_bytes is None:
            raise ValueError("Ascon authentication tag verification failed!")

        message = decrypted_bytes.decode("utf-8")
        print("\n==================================================")
        print("  OPTICAL & HARDWARE AUTHENTICATION SUCCESSFUL    ")
        print("==================================================")
        print(f"Decrypted Message: '{message}'\n")
        return message

    except FileNotFoundError:
        print(f"\nError: File '{filename}' was not found.")

    except Exception as err:
        print("\n==================================================")
        print(f"     HARDWARE AUTHENTICATION FAILED [{err}]         ")
        print("==================================================")
        print("Decryption blocked! Local hardware signature mismatch or tag corruption.\n")
    return None

if __name__ == "__main__":
    target_file = sys.argv[1] if len(sys.argv) > 1 else "encrypted_payload.json"
    decrypt_payload(target_file)
