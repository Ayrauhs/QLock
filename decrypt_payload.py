#The Decryption Vault
import json
import sys
import ascon
from hardware_binder import HardwareBinder
from laser_alignment_gui import run_alignment_hud

def decrypt_payload(filename="encrypted_payload.json"):
    print("\n==================================================")
    print("   QLOCK: OPTICAL & HARDWARE DECRYPTION VAULT     ")
    print("==================================================")

    if not run_alignment_hud():
        print("\n==================================================")
        print("     OPTICAL SECURITY BREACH       ")
        print("==================================================")
        print("Decryption aborted: Laser beam not locked or user cancelled.\n")
        return

    try:
        with open(filename, "r") as f:
            payload = json.load(f)

        ciphertext = bytes.fromhex(payload["ciphertext"])
        nonce = bytes.fromhex(payload["nonce"])
        salt = bytes.fromhex(payload["salt"])
        q_key = bytes.fromhex(payload["q_key"])
        pqc_secret = bytes.fromhex(payload["pqc_secret"])

        print("Querying Hardware Info and HKDF KEY...")
        master_key = HardwareBinder.derive_bound_key(q_key, pqc_secret, salt)

        # Decrypt using Ascon-AEAD lightweight standard (Ascon-128)
        decrypted_bytes = ascon.decrypt(master_key, nonce, b"QLOCK-AUTH-DATA", ciphertext, variant="Ascon-128")
        
        if decrypted_bytes is None:
            raise ValueError("Ascon authentication tag verification failed!")

        print("\n==================================================")
        print("  OPTICAL & HARDWARE AUTHENTICATION SUCCESSFUL    ")
        print("==================================================")
        print(f"Decrypted Message: '{decrypted_bytes.decode('utf-8')}'\n")

    except FileNotFoundError:
        print(f"\nError: File '{filename}' was not found.")
        
    except Exception as err:
        print("\n==================================================")
        print(f"     HARDWARE AUTHENTICATION FAILED [{err}]         ")
        print("==================================================")
        print("Decryption blocked! Local hardware signature mismatch or tag corruption.\n")

if __name__ == "__main__":
    target_file = sys.argv[1] if len(sys.argv) > 1 else "encrypted_payload.json"
    decrypt_payload(target_file)