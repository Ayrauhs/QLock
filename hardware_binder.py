#Extracting the kernel info from the hardware, and then fusing it with the integrated model of QLock
# NOTE: a hardware fingerprint binds data to a machine; it is not a secret. Anyone with local access to the
# legitimate host can read the same identifiers.
import hashlib
import platform
import subprocess

import ascon
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MASTER_KEY_INFO = b"QLock-v1-MasterKey"
SEAL_KEY_INFO = b"QLock-v1-SealKey"


def _run(args) -> str:
    try:
        out = subprocess.check_output(args, stderr=subprocess.DEVNULL, timeout=10)
        return " ".join(out.decode(errors="ignore").split())
    except Exception:
        return ""


def _read(path) -> str:
    try:
        with open(path, "rb") as f:
            return " ".join(f.read().decode(errors="ignore").split())
    except Exception:
        return ""


class HardwareBinder:
    @staticmethod
    def hardware_info() -> bytes:
        base = [platform.system(), platform.machine(), platform.processor()]
        ids, sys_os = [], platform.system()

        if sys_os == "Windows":
            ids.append(_run(["wmic", "csproduct", "get", "uuid"])
                       or _run(["powershell", "-NoProfile", "-Command",
                                "(Get-CimInstance Win32_ComputerSystemProduct).UUID"]))
            ids.append(_run(["wmic", "baseboard", "get", "serialnumber"])
                       or _run(["powershell", "-NoProfile", "-Command",
                                "(Get-CimInstance Win32_BaseBoard).SerialNumber"]))
        elif sys_os == "Linux":
            for path in ("/sys/class/dmi/id/product_uuid", "/sys/class/dmi/id/board_serial", "/etc/machine-id"):
                ids.append(_read(path))
        elif sys_os == "Darwin":
            ids.append(_run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]))

        ids = [i for i in ids if i]
        if not ids:  # never silently fall back to a hostname: that would make the binding meaningless
            raise RuntimeError("No hardware identifier could be read; refusing to derive a hardware-bound key.")
        return "|".join(base + ids).encode()

    @staticmethod
    def hardware_hash() -> bytes:
        """32-byte SHA3-256 hardware fingerprint (H_HW)."""
        return hashlib.sha3_256(HardwareBinder.hardware_info()).digest()

    @staticmethod
    def derive_bound_key(bbm92_key: bytes, pqc_secret: bytes, salt: bytes) -> bytes:
        # IKM = K_BBM92 || S_PQC || H_HW  (all fixed length: 32 + 32 + 32 bytes)
        ikm = bbm92_key + pqc_secret + HardwareBinder.hardware_hash()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=16,  # Exactly 16 bytes (128 bits) required for Ascon-128
            salt=salt,
            info=MASTER_KEY_INFO,
        )
        return hkdf.derive(ikm)

    @staticmethod
    def payload_aad(kem_ciphertext: bytes) -> bytes:
        """Associated data for Ascon: binds the KEM ciphertext to the authentication tag."""
        return b"QLOCK-AUTH-DATA" + hashlib.sha3_256(kem_ciphertext).digest()

    @staticmethod
    def _seal_key(salt: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=16, salt=salt,
                    info=SEAL_KEY_INFO).derive(HardwareBinder.hardware_hash())

    @staticmethod
    def seal_keys(bbm92_key: bytes, kem_secret_key: bytes, salt: bytes, nonce: bytes) -> bytes:
        """Receiver-side key material (K_BBM92 || ML-KEM secret key), encrypted under a hardware-derived key,
        so the payload file never contains usable key material in the clear."""
        return ascon.encrypt(HardwareBinder._seal_key(salt), nonce, b"QLOCK-SEAL",
                             bbm92_key + kem_secret_key, variant="Ascon-128")

    @staticmethod
    def unseal_keys(sealed: bytes, salt: bytes, nonce: bytes) -> tuple[bytes, bytes]:
        pt = ascon.decrypt(HardwareBinder._seal_key(salt), nonce, b"QLOCK-SEAL", sealed, variant="Ascon-128")
        if pt is None:
            raise ValueError("Sealed key blob could not be opened (hardware signature mismatch or corruption).")
        return pt[:32], pt[32:]
