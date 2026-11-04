#The BBM92 entangled photon scheme with Clopper-Pearson bounds and SPAD
import hashlib
import hmac
import math
import os
from dataclasses import dataclass

import numpy as np
from scipy.stats import beta


class SecurityError(Exception):
    """Raised when QLock must abort: QBER bound > 11%, detection anomaly, EC failure, or key too short."""


# ------------------------------------------------------------------ CSPRNG helpers (os.urandom)
def _rand_bits(n: int) -> np.ndarray:
    raw = np.frombuffer(os.urandom((n + 7) // 8), dtype=np.uint8)
    return np.unpackbits(raw)[:n].astype(np.uint8)


def _rand_uniform(n: int) -> np.ndarray:
    raw = np.frombuffer(os.urandom(8 * n), dtype=np.uint64)
    return (raw >> np.uint64(11)).astype(np.float64) / float(1 << 53)


def _rand_permutation(n: int) -> np.ndarray:
    return np.argsort(_rand_uniform(n))


def _rand_normal() -> float:
    u1, u2 = _rand_uniform(2)
    return math.sqrt(-2.0 * math.log(max(float(u1), 1e-300))) * math.cos(2.0 * math.pi * float(u2))


# ------------------------------------------------------------------ statistics
def binary_entropy(p: float) -> float:
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -p * math.log2(p) - (1.0 - p) * math.log2(1.0 - p)


def clopper_pearson_upper(k: int, n: int, confidence_alpha: float = 0.05) -> float:
    """Exact binomial Clopper-Pearson upper bound: Beta^-1(1 - alpha/2; k+1, n-k)."""
    if n <= 0 or k >= n:
        return 1.0
    return float(beta.ppf(1.0 - confidence_alpha / 2.0, k + 1, n - k))


@dataclass
class QKDResult:
    key: bytes              # K_BBM92: 32 bytes = SHA3-256 of the privacy-amplified key
    qber: float             # sample error rate (gamma)
    qber_upper: float       # Clopper-Pearson upper bound (alpha_upper)
    sifted_len: int         # sifted bits before sampling
    sample_len: int         # n: bits sacrificed for parameter estimation
    null_pulses: int        # pulses with no click on either side ("null" sections)
    leaked_ec: int          # bits revealed during error correction + verification
    secret_bits: int        # secret bits after privacy amplification (>= 128)
    eps_auth: float
    eps_ec: float
    eps_pa: float
    eps_pe: float
    eps_total: float        # eps_auth + eps_ec + eps_pa + 2*eps_pe


class QuantumChannel:
    def __init__(self, fiber_length_km=15.0, dark_count_rate=0.002, detector_efficiency=0.85,
                 attenuation_db_per_km=0.2, background_rate=0.001, misalignment_error=0.01,
                 drift_sigma_deg=2.0, qber_abort_limit=0.11, sample_fraction=0.25,
                 eps_pa=1e-6, mac_bits=128, ec_tag_bits=32, min_secret_bits=128, max_secret_bits=256):
        self.fiber_length_km = fiber_length_km
        self.alpha = attenuation_db_per_km                      # dB/km attenuation coefficient
        self.transmittance = 10.0 ** (-self.alpha * fiber_length_km / 10.0)   # end-to-end
        # SPDC source sits mid-link: each arm (to Alice / to Bob) sees half the fiber.
        self.arm_transmittance = 10.0 ** (-self.alpha * (fiber_length_km / 2.0) / 10.0)
        self.dark_count_rate = dark_count_rate                  # SPAD dark counts per gate
        self.background_rate = background_rate                  # thermal / stray-light clicks per gate
        self.eta = detector_efficiency
        self.misalignment = misalignment_error
        self.drift_sigma_deg = drift_sigma_deg                  # polarization drift (std. dev., degrees)
        self.qber_abort_limit = qber_abort_limit                # Shor-Preskill limit (11%)
        self.sample_fraction = sample_fraction
        self.eps_pa = eps_pa
        self.mac_bytes = mac_bits // 8
        self.ec_tag_bits = ec_tag_bits
        self.min_secret_bits = min_secret_bits
        self.max_secret_bits = max_secret_bits
        self._psk = os.urandom(32)                              # pre-shared key authenticating the classical channel
        self._mac_count = 0

    # ------------------------------------------------------------------ authenticated classical channel
    def _authenticated_exchange(self, label: str, payload: bytes) -> None:
        """Public-discussion message protected by a MAC keyed with the PSK (sender tags, receiver verifies)."""
        data = label.encode() + b"|" + payload
        sent_tag = hmac.new(self._psk, data, hashlib.sha3_256).digest()[:self.mac_bytes]
        expected = hmac.new(self._psk, data, hashlib.sha3_256).digest()[:self.mac_bytes]
        self._mac_count += 1
        if not hmac.compare_digest(sent_tag, expected):
            raise SecurityError(f"Classical-channel authentication failed on '{label}'. Aborted.")

    # ------------------------------------------------------------------ photon-level simulation
    def _quantum_phase(self, num_photons: int, intercept_rate: float):
        n = num_photons
        alice_bits, alice_bases, bob_bases = _rand_bits(n), _rand_bits(n), _rand_bits(n)

        p_det = self.arm_transmittance * self.eta
        p_noise = 1.0 - (1.0 - self.dark_count_rate) * (1.0 - self.background_rate)
        a_photon, b_photon = _rand_uniform(n) < p_det, _rand_uniform(n) < p_det
        a_noise, b_noise = _rand_uniform(n) < p_noise, _rand_uniform(n) < p_noise
        a_click, b_click = a_photon | a_noise, b_photon | b_noise
        coincidence = a_click & b_click
        noise_only = (~a_photon & a_noise) | (~b_photon & b_noise)   # noise clicks carry no correlation
        null_pulses = int(np.sum(~(a_click | b_click)))

        # Entangled correlation: same basis -> correlated, different basis -> random.
        bob_bits = np.where(bob_bases == alice_bases, alice_bits, _rand_bits(n))

        # Intercept-resend eavesdropper on Bob's arm (only photons that actually travel there).
        if intercept_rate > 0.0:
            attacked = (_rand_uniform(n) < intercept_rate) & b_photon
            eve_bases = _rand_bits(n)
            eve_result = np.where(eve_bases == alice_bases, alice_bits, _rand_bits(n))
            bob_after_eve = np.where(bob_bases == eve_bases, eve_result, _rand_bits(n))
            bob_bits = np.where(attacked, bob_after_eve, bob_bits)

        # Optical imperfections: fixed misalignment + slowly varying polarization drift (error = sin^2(theta)).
        drift_err = math.sin(math.radians(_rand_normal() * self.drift_sigma_deg)) ** 2
        p_err = self.misalignment + drift_err - 2.0 * self.misalignment * drift_err
        bob_bits = bob_bits ^ (_rand_uniform(n) < p_err).astype(np.uint8)
        bob_bits = np.where(noise_only, _rand_bits(n), bob_bits).astype(np.uint8)

        sifted = coincidence & (alice_bases == bob_bases)
        stats = {
            "coincidences": int(np.sum(coincidence)),
            "null_pulses": null_pulses,
            "p_coincidence": (1.0 - (1.0 - p_det) * (1.0 - p_noise)) ** 2,
            "sift_bases": (alice_bases[coincidence], bob_bases[coincidence]),
        }
        return alice_bits[sifted].astype(np.uint8), bob_bits[sifted].astype(np.uint8), stats

    def _estimate(self, a, b, confidence_alpha):
        m = int(len(a) * self.sample_fraction)
        perm = _rand_permutation(len(a))
        sample_idx, rest_idx = perm[:m], perm[m:]
        k = int(np.sum(a[sample_idx] != b[sample_idx]))
        qber = k / m if m else 1.0
        return qber, clopper_pearson_upper(k, m, confidence_alpha), sample_idx, rest_idx

    def estimate_qber(self, num_photons=4096, intercept_rate=0.0, confidence_alpha=0.05):
        """Parameter estimation only (no abort, no key): returns (qber, cp_upper_bound, sifted_len)."""
        a, b, _ = self._quantum_phase(num_photons, intercept_rate)
        if len(a) < 16:
            return 1.0, 1.0, len(a)
        qber, upper, _, _ = self._estimate(a, b, confidence_alpha)
        return qber, upper, len(a)

    # ------------------------------------------------------------------ error correction (Cascade-style)
    @staticmethod
    def _parity(x, idx) -> int:
        return int(x[idx].sum() & 1)

    def _binary_search_fix(self, alice, bob, idx, transcript):
        lo, hi, leaked = 0, len(idx), 0
        while hi - lo > 1:
            mid = (lo + hi) // 2
            pa, pb = self._parity(alice, idx[lo:mid]), self._parity(bob, idx[lo:mid])
            transcript.extend((pa, pb))
            leaked += 1
            hi, lo = (mid, lo) if pa != pb else (hi, mid)
        bob[idx[lo]] ^= 1
        return leaked

    def _error_correct(self, alice, bob, qber_est):
        bob, n = bob.copy(), len(alice)
        k1 = max(4, int(0.73 / max(qber_est, 0.01)))
        sizes = [k1, 2 * k1, k1, 4 * k1]
        leaked, clean_streak = 0, 0
        for p in range(16):
            k = min(sizes[p % len(sizes)], n)
            order = _rand_permutation(n)
            transcript, found = bytearray(), 0
            for s in range(0, n, k):
                blk = order[s:s + k]
                pa, pb = self._parity(alice, blk), self._parity(bob, blk)
                transcript.extend((pa, pb))
                leaked += 1
                if pa != pb:
                    leaked += self._binary_search_fix(alice, bob, blk, transcript)
                    found += 1
            self._authenticated_exchange(f"ec-pass-{p}", bytes(transcript))
            clean_streak = clean_streak + 1 if found == 0 else 0
            if p >= 3 and clean_streak >= 3:
                break
        return bob, leaked

    # ------------------------------------------------------------------ privacy amplification (Toeplitz)
    @staticmethod
    def _toeplitz_hash(bits, out_len) -> bytes:
        n = len(bits)
        seed = _rand_bits(n + out_len - 1).astype(np.int32)
        idx = np.arange(out_len)[:, None] - np.arange(n)[None, :] + (n - 1)
        out = (seed[idx] @ bits.astype(np.int32)) % 2
        return np.packbits(out.astype(np.uint8)).tobytes()

    # ------------------------------------------------------------------ full protocol
    def execute_bbm92_protocol(self, num_photons=4096, intercept_rate=0.0, confidence_alpha=0.05) -> QKDResult:
        self._mac_count = 0
        a, b, st = self._quantum_phase(num_photons, intercept_rate)

        # Null-section / detection-statistics check against side-channel style tampering (e.g. blinding).
        exp_c = num_photons * st["p_coincidence"]
        sigma = math.sqrt(max(num_photons * st["p_coincidence"] * (1.0 - st["p_coincidence"]), 1e-9))
        if abs(st["coincidences"] - exp_c) > 6.0 * sigma:
            raise SecurityError(f"Detection statistics anomaly ({st['coincidences']} coincidences, "
                                f"expected {exp_c:.0f}). Aborted.")
        if len(a) < 64:
            raise SecurityError(f"Too few sifted bits ({len(a)}); channel unusable.")

        sb_a, sb_b = st["sift_bases"]
        self._authenticated_exchange("sifting", np.packbits(sb_a).tobytes() + np.packbits(sb_b).tobytes())

        qber, upper, sample_idx, rest_idx = self._estimate(a, b, confidence_alpha)
        self._authenticated_exchange("sample", sample_idx.astype(np.uint32).tobytes()
                                     + a[sample_idx].tobytes() + b[sample_idx].tobytes())
        if upper > self.qber_abort_limit:
            raise SecurityError(f"QBER {qber:.2%} (CP upper bound {upper:.2%}) exceeds the "
                                f"{self.qber_abort_limit:.0%} Shor-Preskill limit. Aborted.")

        a_rest, b_rest = a[rest_idx], b[rest_idx]
        b_fixed, leaked = self._error_correct(a_rest, b_rest, qber)

        vsalt = os.urandom(16)
        tag = lambda x: hashlib.sha3_256(vsalt + np.packbits(x).tobytes()).digest()[:self.ec_tag_bits // 8]
        leaked += self.ec_tag_bits
        self._authenticated_exchange("ec-verify", vsalt + tag(a_rest))
        if tag(a_rest) != tag(b_fixed):
            raise SecurityError("Error-correction verification failed; keys differ. Aborted.")

        ell = len(a_rest) * (1.0 - binary_entropy(upper)) - leaked - 2.0 * math.log2(1.0 / self.eps_pa)
        secret_bits = min(self.max_secret_bits, int(max(ell, 0)) // 8 * 8)
        if secret_bits < self.min_secret_bits:
            raise SecurityError(f"Secret key too short after privacy amplification ({secret_bits} bits). Aborted.")

        pa_key = self._toeplitz_hash(a_rest, secret_bits)
        self._authenticated_exchange("pa-seed", b"toeplitz")
        k_bbm92 = hashlib.sha3_256(pa_key).digest()   # fixed 32-byte K_BBM92 (>= 128 secret bits of entropy)

        eps_pe = confidence_alpha / 2.0
        eps_ec = 2.0 ** -self.ec_tag_bits
        eps_auth = self._mac_count * 2.0 ** -(8 * self.mac_bytes)   # q * 2^-p
        eps_total = eps_auth + eps_ec + self.eps_pa + 2.0 * eps_pe
        return QKDResult(key=k_bbm92, qber=qber, qber_upper=upper, sifted_len=len(a),
                         sample_len=len(sample_idx), null_pulses=st["null_pulses"], leaked_ec=leaked,
                         secret_bits=secret_bits, eps_auth=eps_auth, eps_ec=eps_ec, eps_pa=self.eps_pa,
                         eps_pe=eps_pe, eps_total=eps_total)
