#Extracting the kernel info from the hardware, and then fusing it with the integrated model of QLock
import os
import platform
import subprocess
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

class HardwareBinder:
    @staticmethod
    def hardware_info() -> bytes:
        sys_telemetry = bytearray()
        sys_telemetry.extend(platform.system().encode())
        sys_telemetry.extend(platform.machine().encode())
        sys_telemetry.extend(platform.processor().encode())
        
        sys_os = platform.system()
        try:
            if sys_os == "Windows":
                uuid_cmd = subprocess.check_output(
                    "wmic csproduct get uuid", shell=True, stderr=subprocess.STDOUT
                ).decode(errors="ignore")
                board_cmd = subprocess.check_output(
                    "wmic baseboard get serialnumber", shell=True, stderr=subprocess.STDOUT
                ).decode(errors="ignore")
                sys_telemetry.extend(uuid_cmd.encode())
                sys_telemetry.extend(board_cmd.encode())
            elif sys_os == "Linux":
                for path in ["/sys/class/dmi/id/product_uuid", "/sys/class/dmi/id/board_serial"]:
                    if os.path.exists(path):
                        with open(path, "rb") as f:
                            sys_telemetry.extend(f.read())
        except Exception:
            sys_telemetry.extend(platform.node().encode())

        return bytes(sys_telemetry)

    @staticmethod
    def derive_bound_key(bbm92_key: bytes, pqc_secret: bytes, salt: bytes) -> bytes:
        # Integration with BBM92 + PQC and hardware telemetry
        hw_fingerprint = HardwareBinder.hardware_info()
        hw_hash = hashlib.sha3_256(hw_fingerprint).digest()
        
        ikm = bbm92_key + pqc_secret + hw_hash
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=16,  # Exactly 16 bytes (128 bits) required for Ascon-128
            salt=salt,
            info=b"QLOCK-ULTIMATE-FUSION-V2",
        )
        return hkdf.derive(ikm)