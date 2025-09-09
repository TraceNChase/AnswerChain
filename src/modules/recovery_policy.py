#!/usr/bin/env python3
# src/policy/recovery_policy.py

from __future__ import annotations
import base64, hashlib
from typing import List, Optional, Tuple

# Depend on existing crypto bridge for HKDF/HMAC if available; fall back to hashlib.
try:
    from modules.crypto_bridge import hkdf_sha256
    def _hkdf(ikm: bytes, salt: bytes, info: bytes, dk_len: int) -> bytes:
        return hkdf_sha256(ikm, salt, info, dk_len)
except Exception:
    def _hkdf(ikm: bytes, salt: bytes, info: bytes, dk_len: int) -> bytes:
        prk = hashlib.sha256(salt + ikm).digest()
        out = b""
        t = b""
        while len(out) < dk_len:
            t = hashlib.sha256(t + info + prk).digest()
            out += t
        return out[:dk_len]

def _b64_loose(s: str) -> Optional[bytes]:
    """Decode standard/url-safe Base64 with tolerant padding. Returns None if invalid."""
    txt = s.strip()
    pad = "=" * (-len(txt) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder(txt + pad)
        except Exception:
            continue
    return None

def _fingerprint_to_bytes(fp: str | bytes) -> bytes:
    if isinstance(fp, bytes):
        return fp
    return hashlib.sha3_256(fp.encode("utf-8")).digest()

def deterministic_decoy_index(fingerprint: bytes, decoy_count: int) -> int:
    # Use HKDF over the fingerprint so output is stable for the same inputs
    ok = max(1, int(decoy_count))
    key = _hkdf(ikm=fingerprint, salt=b"AC:decoy-salt", info=b"AC:decoy-index", dk_len=4)
    val = int.from_bytes(key, "big")
    return val % ok

def decide_output(
    reconstructed_b64: Optional[str],
    decoys: List[str],
    fingerprint: bytes
) -> Tuple[str, bool]:
    """
    Returns (text_to_emit, is_real). Never reveals failure; always returns plausible text.
    """
    # Try real first
    if reconstructed_b64:
        real_bytes = _b64_loose(reconstructed_b64)
        if real_bytes is not None:
            try:
                text = real_bytes.decode("utf-8")
                return text, True
            except UnicodeDecodeError:
                # Real exists but isn't UTF-8; still emit opaque base64
                return reconstructed_b64, True

    # Otherwise deterministic decoy; if none, emit pseudorandom-looking token
    if decoys:
        idx = deterministic_decoy_index(fingerprint, len(decoys))
        return decoys[idx], False

    # Pseudorandom fallback (no decoys present)
    token_b64 = base64.urlsafe_b64encode(_hkdf(fingerprint, b"AC:rand-salt", b"AC:rand", 24)).rstrip(b"=").decode("ascii")
    return token_b64, False
