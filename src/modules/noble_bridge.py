# noble_bridge.py
# Python wrapper for AnswerChain cryptographic Node.js bridge.
# Spawns a local Node.js subprocess that loads noble-hashes.js and noble-ciphers.js bundles.
# Provides a simple, synchronous API.
from __future__ import annotations

import base64
import json
import os
import subprocess
import threading
import uuid
from dataclasses import dataclass
from typing import Optional, Dict, Any

class BridgeError(Exception):
    pass

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')

def _b64d(s: Optional[str]) -> bytes:
    if s is None:
        return b""
    return base64.b64decode(s, validate=True)

@dataclass
class _Request:
    id: str
    op: str
    args: Dict[str, Any]

class NobleBridge:
    """
    Usage:
        with NobleBridge(node_path='node', js_dir='/path/to/js') as nb:
            out = nb.sha3_256(b'data')
    """
    def __init__(self, node_path: str = 'node', js_dir: str = '.', script_name: str = 'bridge.js', timeout: float = 30.0):
        self.node_path = node_path
        self.script_path = os.path.join(js_dir, script_name)
        self.proc = None  # type: Optional[subprocess.Popen]
        self.timeout = timeout
        self._lock = threading.Lock()

    def start(self):
        if self.proc is not None:
            return
        if not os.path.exists(self.script_path):
            raise BridgeError(f"bridge script not found: {self.script_path}")
        # Ensure noble bundles exist
        for bundle in ('noble-hashes.js', 'noble-ciphers.js'):
            p = os.path.join(os.path.dirname(self.script_path), bundle)
            if not os.path.exists(p):
                raise BridgeError(f"required bundle missing: {bundle} at {p}")
        self.proc = subprocess.Popen(
            [self.node_path, self.script_path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, universal_newlines=True
        )

    def close(self):
        if self.proc:
            try:
                self.proc.stdin.close()
            except Exception:
                pass
            try:
                self.proc.terminate()
            except Exception:
                pass
            self.proc = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def _rpc(self, op: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if self.proc is None:
            self.start()
        assert self.proc is not None and self.proc.stdin and self.proc.stdout
        req = _Request(id=str(uuid.uuid4()), op=op, args=args)
        line = json.dumps(req.__dict__, separators=(',', ':')) + '\n'
        with self._lock:
            self.proc.stdin.write(line)
            self.proc.stdin.flush()
            # Simple line-based response; production could implement framing & timeouts.
            resp_line = self.proc.stdout.readline()
        if not resp_line:
            err = self.proc.stderr.read()
            raise BridgeError(f"no response from bridge; stderr: {err}")
        try:
            resp = json.loads(resp_line)
        except json.JSONDecodeError as e:
            raise BridgeError(f"invalid JSON from bridge: {resp_line!r}") from e
        if not resp.get('ok'):
            raise BridgeError(resp.get('error', 'unknown error'))
        return resp['result']

    # === Hashes, MACs, KDFs ===
    def sha3_256(self, data: bytes) -> bytes:
        res = self._rpc('sha3_256', {'data': _b64(data)})
        return _b64d(res['digest'])

    def hmac_sha256(self, key: bytes, data: bytes) -> bytes:
        res = self._rpc('hmac_sha256', {'key': _b64(key), 'data': _b64(data)})
        return _b64d(res['digest'])

    def hkdf_sha256(self, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
        res = self._rpc('hkdf_sha256', {
            'ikm': _b64(ikm), 'salt': _b64(salt), 'info': _b64(info), 'length': int(length)
        })
        return _b64d(res['okm'])

    # === Argon2id ===
    def argon2id(self, password: bytes, salt: bytes, t: int = 2, m: int = 65536, p: int = 1, dkLen: int = 32, version: int = 19) -> bytes:
        if len(salt) < 16:
            raise ValueError("salt must be at least 16 bytes")
        res = self._rpc('argon2id', {
            'password': _b64(password), 'salt': _b64(salt),
            't': int(t), 'm': int(m), 'p': int(p), 'dkLen': int(dkLen), 'version': int(version)
        })
        return _b64d(res['okm'])

    # === AEAD ===
    def aes_gcm_encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        if len(key) != 32: raise ValueError("AES-256-GCM key must be 32 bytes")
        if len(nonce) != 12: raise ValueError("AES-GCM nonce must be 12 bytes")
        args = {'key': _b64(key), 'nonce': _b64(nonce), 'plaintext': _b64(plaintext)}
        if aad is not None: args['aad'] = _b64(aad)
        res = self._rpc('aes_gcm_encrypt', args)
        return _b64d(res['ciphertext'])

    def aes_gcm_decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
        if len(key) != 32: raise ValueError("AES-256-GCM key must be 32 bytes")
        if len(nonce) != 12: raise ValueError("AES-GCM nonce must be 12 bytes")
        args = {'key': _b64(key), 'nonce': _b64(nonce), 'ciphertext': _b64(ciphertext)}
        if aad is not None: args['aad'] = _b64(aad)
        res = self._rpc('aes_gcm_decrypt', args)
        return _b64d(res['plaintext'])

    def chacha20poly1305_encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        if len(key) != 32: raise ValueError("ChaCha20-Poly1305 key must be 32 bytes")
        if len(nonce) != 12: raise ValueError("IETF ChaCha20-Poly1305 nonce must be 12 bytes")
        args = {'key': _b64(key), 'nonce': _b64(nonce), 'plaintext': _b64(plaintext)}
        if aad is not None: args['aad'] = _b64(aad)
        res = self._rpc('chacha20poly1305_encrypt', args)
        return _b64d(res['ciphertext'])

    def chacha20poly1305_decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
        if len(key) != 32: raise ValueError("ChaCha20-Poly1305 key must be 32 bytes")
        if len(nonce) != 12: raise ValueError("IETF ChaCha20-Poly1305 nonce must be 12 bytes")
        args = {'key': _b64(key), 'nonce': _b64(nonce), 'ciphertext': _b64(ciphertext)}
        if aad is not None: args['aad'] = _b64(aad)
        res = self._rpc('chacha20poly1305_decrypt', args)
        return _b64d(res['plaintext'])

    def xchacha20poly1305_encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        if len(key) != 32: raise ValueError("XChaCha20-Poly1305 key must be 32 bytes")
        if len(nonce) != 24: raise ValueError("XChaCha20-Poly1305 nonce must be 24 bytes")
        args = {'key': _b64(key), 'nonce': _b64(nonce), 'plaintext': _b64(plaintext)}
        if aad is not None: args['aad'] = _b64(aad)
        res = self._rpc('xchacha20poly1305_encrypt', args)
        return _b64d(res['ciphertext'])

    def xchacha20poly1305_decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
        if len(key) != 32: raise ValueError("XChaCha20-Poly1305 key must be 32 bytes")
        if len(nonce) != 24: raise ValueError("XChaCha20-Poly1305 nonce must be 24 bytes")
        args = {'key': _b64(key), 'nonce': _b64(nonce), 'ciphertext': _b64(ciphertext)}
        if aad is not None: args['aad'] = _b64(aad)
        res = self._rpc('xchacha20poly1305_decrypt', args)
        return _b64d(res['plaintext'])

    # === Constant-time equality over Node (timingSafeEqual) ===
    def ct_equal(self, a: bytes, b: bytes) -> bool:
        res = self._rpc('ct_equal', {'a': _b64(a), 'b': _b64(b)})
        return bool(res['equal'])
