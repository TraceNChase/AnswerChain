#!/usr/bin/env python3
# src/modules/crypto_bridge.py
# General-purpose Noble bridge (stdio JSON). Safe, minimal surface.

from __future__ import annotations
import base64, json, subprocess, os
from typing import Optional
from pathlib import Path

# Compute paths relative to this module
MODULE_DIR = Path(__file__).resolve().parent
SRC_DIR = MODULE_DIR.parent
ROOT_DIR = SRC_DIR.parent
BRIDGE_JS = ROOT_DIR / "bridge" / "crypto-bridge.js"

NODE_PATH = os.getenv("NODE_BIN", "node")

def _b64u(data: bytes) -> str:
    # RFC 4648 “URL and Filename Safe” alphabet; we strip '=' padding
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _unb64u(s: str) -> bytes:
    # Add required '=' padding safely before decoding
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _call(req: dict) -> dict:
    if not BRIDGE_JS.exists():
        raise FileNotFoundError(f"Bridge script not found at {BRIDGE_JS}")

    # Send JSON as base64url to Node
    raw_in = _b64u(json.dumps(req).encode("utf-8")).encode("ascii")
    p = subprocess.run(
        [NODE_PATH, str(BRIDGE_JS)],
        input=raw_in,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if p.returncode != 0:
        raise RuntimeError(f"node exited {p.returncode}: {p.stderr.decode('utf-8', 'ignore')}")

    if not p.stdout:
        raise RuntimeError("bridge returned empty stdout")

    try:
        # Node returns base64url(JSON). Decode with padding tolerance.
        out_b64u = p.stdout.decode("ascii", "strict").strip()
        resp = json.loads(_unb64u(out_b64u).decode("utf-8"))
    except Exception as e:
        raise RuntimeError(f"invalid bridge response: {e}")

    if not resp.get("ok"):
        raise RuntimeError(f"bridge error: {resp.get('error')}")
    return resp

# ==== Public API ====

def argon2id(password: bytes, salt: bytes, m_cost: int, t: int, p: int, dk_len: int) -> bytes:
    resp = _call({
        "op": "argon2id",
        "password_b64": _b64u(password),
        "salt_b64": _b64u(salt),
        "mCost": int(m_cost), "t": int(t), "p": int(p), "dkLen": int(dk_len),
    })
    return _unb64u(resp["key_b64"])

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, dk_len: int) -> bytes:
    resp = _call({
        "op": "hkdf_sha256",
        "ikm_b64": _b64u(ikm), "salt_b64": _b64u(salt), "info_b64": _b64u(info),
        "dkLen": int(dk_len),
    })
    return _unb64u(resp["key_b64"])

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    resp = _call({"op": "hmac_sha256", "key_b64": _b64u(key), "data_b64": _b64u(data)})
    return _unb64u(resp["tag_b64"])

def sha3_256(data: bytes) -> bytes:
    resp = _call({"op": "sha3_256", "data_b64": _b64u(data)})
    return _unb64u(resp["hash_b64"])

def aes_gcm_encrypt(key: bytes, nonce12: bytes, pt: bytes, aad: Optional[bytes]=None) -> bytes:
    if len(nonce12) != 12:
        raise ValueError("AES-GCM requires 12-byte nonce")
    req = {"op": "aes_gcm_encrypt", "key_b64": _b64u(key), "nonce_b64": _b64u(nonce12), "pt_b64": _b64u(pt)}
    if aad is not None:
        req["aad_b64"] = _b64u(aad)
    resp = _call(req)
    return _unb64u(resp["ct_b64"])

def aes_gcm_decrypt(key: bytes, nonce12: bytes, ct: bytes, aad: Optional[bytes]=None) -> bytes:
    if len(nonce12) != 12:
        raise ValueError("AES-GCM requires 12-byte nonce")
    req = {"op": "aes_gcm_decrypt", "key_b64": _b64u(key), "nonce_b64": _b64u(nonce12), "ct_b64": _b64u(ct)}
    if aad is not None:
        req["aad_b64"] = _b64u(aad)
    resp = _call(req)
    return _unb64u(resp["pt_b64"])

def chacha20poly1305_encrypt(key: bytes, nonce12: bytes, pt: bytes, aad: Optional[bytes]=None) -> bytes:
    if len(nonce12) != 12:
        raise ValueError("ChaCha20-Poly1305 requires 12-byte nonce")
    req = {"op": "chacha20poly1305_encrypt", "key_b64": _b64u(key), "nonce_b64": _b64u(nonce12), "pt_b64": _b64u(pt)}
    if aad is not None:
        req["aad_b64"] = _b64u(aad)
    resp = _call(req)
    return _unb64u(resp["ct_b64"])

def chacha20poly1305_decrypt(key: bytes, nonce12: bytes, ct: bytes, aad: Optional[bytes]=None) -> bytes:
    if len(nonce12) != 12:
        raise ValueError("ChaCha20-Poly1305 requires 12-byte nonce")
    req = {"op": "chacha20poly1305_decrypt", "key_b64": _b64u(key), "nonce_b64": _b64u(nonce12), "ct_b64": _b64u(ct)}
    if aad is not None:
        req["aad_b64"] = _b64u(aad)
    resp = _call(req)
    return _unb64u(resp["pt_b64"])

def xchacha20poly1305_encrypt(key: bytes, nonce24: bytes, pt: bytes, aad: Optional[bytes]=None) -> bytes:
    if len(nonce24) != 24:
        raise ValueError("XChaCha20-Poly1305 requires 24-byte nonce")
    req = {"op": "xchacha20poly1305_encrypt", "key_b64": _b64u(key), "nonce_b64": _b64u(nonce24), "pt_b64": _b64u(pt)}
    if aad is not None:
        req["aad_b64"] = _b64u(aad)
    resp = _call(req)
    return _unb64u(resp["ct_b64"])

def xchacha20poly1305_decrypt(key: bytes, nonce24: bytes, ct: bytes, aad: Optional[bytes]=None) -> bytes:
    if len(nonce24) != 24:
        raise ValueError("XChaCha20-Poly1305 requires 24-byte nonce")
    req = {"op": "xchacha20poly1305_decrypt", "key_b64": _b64u(key), "nonce_b64": _b64u(nonce24), "ct_b64": _b64u(ct)}
    if aad is not None:
        req["aad_b64"] = _b64u(aad)
    resp = _call(req)
    return _unb64u(resp["pt_b64"])

def random_bytes(n: int) -> bytes:
    resp = _call({"op": "random_bytes", "n": int(n)})
    return _unb64u(resp["bytes_b64"])

def consttime_equal(a: bytes, b: bytes) -> bool:
    resp = _call({"op": "consttime_equal", "a_b64": _b64u(a), "b_b64": _b64u(b)})
    return bool(resp["equal"])
