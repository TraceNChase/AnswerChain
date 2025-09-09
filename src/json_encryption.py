#!/usr/bin/env python3
"""
json_encryption.py

Minimal AEAD helper wrappers for encrypting/decrypting JSON-compatible byte blobs
using only cryptographic primitives already present in the codebase via
modules.crypto_bridge. No external Python libraries are introduced and no custom
cryptographic algorithms are implemented here.

These helpers are optional and kept generic; the main application flow derives
keys from security-question answers and orchestrates Shamir's Secret Sharing,
ensuring the encrypted content is unlockable only by providing the correct
sequence of answers. This module simply provides a small, reusable surface for
AEAD operations.
"""
from __future__ import annotations
from typing import Optional, Dict, Any
import base64

from modules.crypto_bridge import (
    random_bytes,
    # Preferred algorithms (if available in the bridge)
    # We will probe availability at runtime via try/except.
)

# We access crypto functions dynamically to avoid hard dependencies when a given
# algorithm is not exposed by the bridge on a platform.
from modules import crypto_bridge as CF


def select_preferred_aead_algorithm() -> str:
    """
    Pick the strongest available AEAD algorithm from the bridge, in order of
    preference. Fallbacks are provided to maintain compatibility.
    """
    if hasattr(CF, "xchacha20poly1305_encrypt") and hasattr(CF, "xchacha20poly1305_decrypt"):
        return "xchacha20poly1305"
    # AES-GCM-SIV not explicitly exposed by the current bridge; keep standard AES-GCM next
    if hasattr(CF, "aes_gcm_encrypt") and hasattr(CF, "aes_gcm_decrypt"):
        return "aes256gcm"
    if hasattr(CF, "chacha20poly1305_encrypt") and hasattr(CF, "chacha20poly1305_decrypt"):
        return "chacha20poly1305"
    # Final fallback (should not happen if bridge is present)
    return "aes256gcm"


def aead_encrypt(plaintext: bytes, key: bytes, aad: Optional[bytes] = None, algorithm: Optional[str] = None) -> Dict[str, Any]:
    """
    Encrypt a plaintext using the specified or preferred AEAD algorithm exposed by
    the crypto bridge. Returns a dict suitable for JSON serialization with fields:
      - ciphertext (base64 string)
      - nonce (base64 string)
      - algorithm (string)
    """
    alg = (algorithm or select_preferred_aead_algorithm()).lower()
    if alg == "xchacha20poly1305" and hasattr(CF, "xchacha20poly1305_encrypt"):
        nonce = random_bytes(24)
        ct = CF.xchacha20poly1305_encrypt(key, nonce, plaintext, aad=aad)
        return {
            "ciphertext": base64.b64encode(ct).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "algorithm": alg,
        }
    if alg == "chacha20poly1305" and hasattr(CF, "chacha20poly1305_encrypt"):
        nonce = random_bytes(12)
        ct = CF.chacha20poly1305_encrypt(key, nonce, plaintext, aad=aad)
        return {
            "ciphertext": base64.b64encode(ct).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "algorithm": alg,
        }

    # Default to AES-256-GCM
    nonce = random_bytes(12)
    ct = CF.aes_gcm_encrypt(key, nonce, plaintext, aad=aad)
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "algorithm": "aes256gcm",
    }


def aead_decrypt(entry: Dict[str, Any], key: bytes, aad: Optional[bytes] = None) -> bytes:
    """
    Decrypts a dict produced by aead_encrypt().
    """
    alg = (entry.get("algorithm") or "aes256gcm").lower()
    ct = base64.b64decode(entry.get("ciphertext", ""))
    nonce = base64.b64decode(entry.get("nonce", ""))

    if alg == "xchacha20poly1305" and hasattr(CF, "xchacha20poly1305_decrypt"):
        return CF.xchacha20poly1305_decrypt(key, nonce, ct, aad=aad)
    if alg == "chacha20poly1305" and hasattr(CF, "chacha20poly1305_decrypt"):
        return CF.chacha20poly1305_decrypt(key, nonce, ct, aad=aad)
    return CF.aes_gcm_decrypt(key, nonce, ct, aad=aad)

