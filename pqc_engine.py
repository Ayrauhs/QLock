#Integration of ML-KEM-768 Scheme with Post Quantum Cryptography for secure transmission
# Backends (first available wins): liboqs-python ("ML-KEM-768" / "Kyber768"), then kyber-py (pure-Python ML-KEM-768).
# There is deliberately NO fake/fallback KEM: if no real implementation is installed, the engine refuses to start.

try:
    import oqs
    LIBOQS_AVAILABLE = hasattr(oqs, "KeyEncapsulation")
except Exception:
    oqs = None
    LIBOQS_AVAILABLE = False

try:
    from kyber_py.ml_kem import ML_KEM_768
    KYBER_PY_AVAILABLE = True
except Exception:
    ML_KEM_768 = None
    KYBER_PY_AVAILABLE = False


def _enabled_kems():
    for name in ("get_enabled_kem_mechanisms", "get_enabled_KEM_mechanisms"):
        fn = getattr(oqs, name, None)
        if fn:
            return list(fn())
    return []


class MLKEM768Engine:
    def __init__(self):
        self.backend = None
        if LIBOQS_AVAILABLE:
            enabled = _enabled_kems()
            for name in ("ML-KEM-768", "Kyber768"):
                if name in enabled:
                    self.backend, self.alg_name = "liboqs", name
                    break
        if self.backend is None and KYBER_PY_AVAILABLE:
            self.backend, self.alg_name = "kyber-py", "ML-KEM-768"
        if self.backend is None:
            raise RuntimeError("No ML-KEM-768 implementation found. Install one of: "
                               "'pip install kyber-py' (pure Python) or liboqs-python (needs the liboqs C library).")

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Ephemeral key pair. Returns (public_key, secret_key)."""
        if self.backend == "liboqs":
            with oqs.KeyEncapsulation(self.alg_name) as kem:
                pk = kem.generate_keypair()
                return pk, kem.export_secret_key()
        ek, dk = ML_KEM_768.keygen()
        return ek, dk

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Returns (kem_ciphertext, 256-bit shared_secret)."""
        if self.backend == "liboqs":
            with oqs.KeyEncapsulation(self.alg_name) as kem:
                return kem.encap_secret(public_key)
        shared, ct = ML_KEM_768.encaps(public_key)
        return ct, shared

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Recovers the 256-bit shared secret with the secret key."""
        if self.backend == "liboqs":
            with oqs.KeyEncapsulation(self.alg_name, secret_key=private_key) as kem:
                return kem.decap_secret(ciphertext)
        return ML_KEM_768.decaps(private_key, ciphertext)
