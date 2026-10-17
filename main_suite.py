#The GODFATHER of QLock. Acts as a control/execution unit along with encryption
import json
import os
import sys
import matplotlib.pyplot as plt
import numpy as np
import ascon

from quantum_sim import KeyDistribution
from pqc_engine import MLKEM768Engine
from hardware_binder import HardwareBinder


class SecurityError(Exception):
    pass


class QLockSystem:
    def __init__(self):
        self.qkd_sim = KeyDistribution(fiber_length_km=15.0)
        self.pqc = MLKEM768Engine()
        self.qber_abort_limit = 0.11

    def execute_hybrid_encryption(self, plaintext: str) -> dict:
        print("\nRunning BBM92 Quantum Key Distribution over optical channel...")
        q_key, qber, sift_len = self.qkd_sim.execute_bbm92_protocol(num_photons=4096, intercept_rate=0.0)
        print(f"      - Sifted Key Length: {sift_len} bits | Channel QBER: {qber:.2%}")

        if qber > self.qber_abort_limit:
            raise SecurityError(f"QBER limit exceeded ({qber:.2%} > 11.00%). Execution aborted!")

        print("Performing Crystals-Kyber Post-Quantum Encapsulation...")
        pk, sk = self.pqc.generate_keypair()
        ct, pqc_secret = self.pqc.encapsulate(pk)

        print("Fusing Entropy Sources via KDF & Hardware Binding...")
        salt = os.urandom(16)
        nonce = os.urandom(16)  # Ascon 16-byte nonce
        master_key = HardwareBinder.derive_bound_key(q_key, pqc_secret, salt)

        # Lightweight encapsulation via Ascon-AEAD (Ascon-128 requires 16-byte key & 16-byte nonce)
        ciphertext = ascon.encrypt(master_key, nonce, b"QLOCK-AUTH-DATA", plaintext.encode("utf-8"), variant="Ascon-128")

        return {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "salt": salt,
            "q_key": q_key,
            "pqc_secret": pqc_secret,
            "qber": qber,
        }

    def run_empirical_disturbance_benchmark(self):
        print("\nRunning Empirical BBM92 Optical Interception Sweep...")
        interception_rates = np.linspace(0.0, 1.0, 21)
        qber_results = []
        qber_std = []

        for rate in interception_rates:
            trials = []
            for _ in range(15):
                _, qber, _ = self.qkd_sim.execute_bbm92_protocol(num_photons=2048, intercept_rate=rate)
                trials.append(qber * 100.0)
            qber_results.append(np.mean(trials))
            qber_std.append(np.std(trials))

        plt.figure(figsize=(9, 5.5))
        plt.errorbar(
            interception_rates * 100.0,
            qber_results,
            yerr=qber_std,
            fmt="-o",
            color="#0055ff",
            ecolor="#ff4444",
            errorevery=1,
            capsize=4,
            linewidth=2,
            label="Measured BBM92 QBER (%)",
        )
        plt.axhline(y=11.0, color="red", linestyle="--", linewidth=1.5, label="Security Threshold (11%)")
        plt.title("Quantum Bit Error Rate (QBER) vs. Eavesdropping Interception Probability", fontsize=11)
        plt.xlabel("Eavesdropper Interception Rate $E$ (%)", fontsize=10)
        plt.ylabel("Measured Quantum Bit Error Rate (QBER) (%)", fontsize=10)
        plt.grid(True, linestyle=":", alpha=0.6)
        plt.legend(loc="upper left")
        plt.tight_layout()

        out_file = "disturbance_graph.png"
        plt.savefig(out_file, dpi=300)
        print(f"Disturbance plot saved to: '{out_file}'")
        plt.close()


def run_interactive_menu():
    app = QLockSystem()

    while True:
        print("\n==================================================")
        print("   QLOCK: HYBRID SECURITY SUITE (BBM92 + ASCON)   ")
        print("==================================================")
        print("1. Encrypt Message & Export JSON File")
        print("2. Run QBER Disturbance Benchmark Plot")
        print("3. Exit")

        choice = input("\nSelect an option (1-3): ").strip()

        if choice == "1":
            secret_message = input("\nEnter the message to encrypt: ").strip()
            if not secret_message:
                secret_message = "Ultimate Security Verified Payload"

            try:
                pocket = app.execute_hybrid_encryption(secret_message)
                payload_data = {
                    "ciphertext": pocket["ciphertext"].hex(),
                    "nonce": pocket["nonce"].hex(),
                    "salt": pocket["salt"].hex(),
                    "q_key": pocket["q_key"].hex(),
                    "pqc_secret": pocket["pqc_secret"].hex(),
                    "qber": pocket["qber"]
                }
                
                with open("encrypted_payload.json", "w") as f:
                    json.dump(payload_data, f, indent=4)

                print("\nEncryption successful!")
                print("Output saved to 'encrypted_payload.json'")
                print("Run 'python decrypt_payload.py' to test hardware decryption.")
            except Exception as e:
                print(f"\nEncryption Failed: {e}")

        elif choice == "2":
            app.run_empirical_disturbance_benchmark()

        elif choice == "3":
            print("\nExiting QLock Suite.")
            sys.exit(0)

if __name__ == "__main__":
    run_interactive_menu()