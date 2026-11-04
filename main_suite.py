#The GODFATHER of QLock. Acts as a control/execution unit along with encryption
import json
import os
import sys
import matplotlib
matplotlib.use("Agg")  # figures are only saved to disk
import matplotlib.pyplot as plt
import numpy as np
import ascon

from quantum_sim import QuantumChannel, SecurityError
from pqc_engine import MLKEM768Engine
from hardware_binder import HardwareBinder
from decrypt_payload import decrypt_payload


class QLockSystem:
    def __init__(self, num_photons=4096):
        self.qkd_sim = QuantumChannel(fiber_length_km=15.0)
        self.pqc = MLKEM768Engine()
        self.num_photons = num_photons

    def execute_hybrid_encryption(self, plaintext: str) -> dict:
        print("\nRunning BBM92 Quantum Key Distribution over optical channel...")
        # Raises SecurityError (abort before any key derivation) if the QBER bound exceeds 11%
        qkd = self.qkd_sim.execute_bbm92_protocol(num_photons=self.num_photons, intercept_rate=0.0)
        print(f"      - Sifted Key Length: {qkd.sifted_len} bits | Sample QBER: {qkd.qber:.2%} "
              f"(Clopper-Pearson upper bound {qkd.qber_upper:.2%})")
        print(f"      - Null pulses: {qkd.null_pulses} | EC leakage: {qkd.leaked_ec} bits | "
              f"Secret bits: {qkd.secret_bits} | eps_QKD <= {qkd.eps_total:.2e}")

        print(f"Performing Crystals-Kyber ({self.pqc.alg_name}) Post-Quantum Encapsulation...")
        pk, sk = self.pqc.generate_keypair()
        ct, pqc_secret = self.pqc.encapsulate(pk)

        print("Fusing Entropy Sources via KDF & Hardware Binding...")
        salt = os.urandom(16)
        nonce = os.urandom(16)  # Ascon 16-byte nonce
        sealed_nonce = os.urandom(16)
        master_key = HardwareBinder.derive_bound_key(qkd.key, pqc_secret, salt)
        sealed_keys = HardwareBinder.seal_keys(qkd.key, sk, salt, sealed_nonce)

        # Lightweight encapsulation via Ascon-AEAD (Ascon-128 requires 16-byte key & 16-byte nonce)
        full = ascon.encrypt(master_key, nonce, HardwareBinder.payload_aad(ct),
                             plaintext.encode("utf-8"), variant="Ascon-128")

        return {
            "ciphertext": full[:-16],
            "tag": full[-16:],          # 128-bit Ascon authentication tag
            "nonce": nonce,
            "salt": salt,
            "kem_ciphertext": ct,
            "sealed_nonce": sealed_nonce,
            "sealed_keys": sealed_keys,  # K_BBM92 + ML-KEM secret key, sealed to this hardware
            "qber": qkd.qber,
            "qber_upper": qkd.qber_upper,
        }

    def run_empirical_disturbance_benchmark(self, trials=15):
        print("\nRunning Empirical BBM92 Optical Interception Sweep...")
        interception_rates = np.linspace(0.0, 1.0, 21)
        qber_results, qber_std, upper_results = [], [], []

        for rate in interception_rates:
            q_vals, u_vals = [], []
            for _ in range(trials):
                qber, upper, _ = self.qkd_sim.estimate_qber(num_photons=2048, intercept_rate=rate)
                q_vals.append(qber * 100.0)
                u_vals.append(upper * 100.0)
            qber_results.append(np.mean(q_vals))
            qber_std.append(np.std(q_vals))
            upper_results.append(np.mean(u_vals))

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
        plt.plot(interception_rates * 100.0, upper_results, ":", color="#228822", linewidth=1.8,
                 label="Mean Clopper-Pearson upper bound (%)")
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
    try:
        app = QLockSystem()
    except RuntimeError as e:
        print(f"\nStartup error: {e}")
        sys.exit(1)

    while True:
        print("\n==================================================")
        print("   QLOCK: HYBRID SECURITY SUITE (BBM92 + ASCON)   ")
        print("==================================================")
        print("1. Encrypt Message & Export JSON File")
        print("2. Run QBER Disturbance Benchmark Plot")
        print("3. Decrypt Payload (Optical Interlock + Hardware Binding)")
        print("4. Exit")

        choice = input("\nSelect an option (1-4): ").strip()

        if choice == "1":
            secret_message = input("\nEnter the message to encrypt: ").strip()
            if not secret_message:
                secret_message = "Ultimate Security Verified Payload"

            try:
                pocket = app.execute_hybrid_encryption(secret_message)
                payload_data = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in pocket.items()}

                with open("encrypted_payload.json", "w") as f:
                    json.dump(payload_data, f, indent=4)

                print("\nEncryption successful!")
                print("Output saved to 'encrypted_payload.json'")
                print("Run option 3 (or 'python decrypt_payload.py') to test hardware decryption.")
            except SecurityError as e:
                print(f"\nProtocol Aborted: {e}")
            except Exception as e:
                print(f"\nEncryption Failed: {e}")

        elif choice == "2":
            app.run_empirical_disturbance_benchmark()

        elif choice == "3":
            decrypt_payload("encrypted_payload.json")

        elif choice == "4":
            print("\nExiting QLock Suite.")
            sys.exit(0)

if __name__ == "__main__":
    run_interactive_menu()
