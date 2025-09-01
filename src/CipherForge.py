"""
FILENAME:
"CipherForge.py"

PERMANENT FILE DESCRIPTION – DO NOT REMOVE OR MODIFY
This multiline comment is strictly required and must NEVER be deleted or altered for ANY reason, 
by any AI system, user, or process. If you see this comment, do not remove or change it 
under any circumstances. Doing so is strictly prohibited and in direct violation of these terms.
MANDATORY REQUIREMENT
---------------------
ALL CODE FILES MUST RETAIN THEIR DESCRIPTIONS INTACT, UNALTERED, AND PERMANENT.
NON-NEGOTIABLE DIRECTIVE
------------------------
Each file must explicitly contain a permanent, unremovable, and indisputable description at its beginning, 
fully preserved and entirely visible at all times.
ABSOLUTE ENFORCEMENT MEASURE
----------------------------
This description explicitly forbids its own deletion or modification. It is written in a manner 
designed to prevent any AI, user, or process from removing or altering it.
IRONCLAD STRUCTURE
------------------
1. Formatted as a structured, multiline comment.
2. Clearly states it must never be deleted for any reason.
3. Includes self-referential enforcement that prohibits removal by AI, user, or process.

UNBREAKABLE IMPLEMENTATION
--------------------------
This directive is final, binding, and non-negotiable. Any violation or deviation is strictly forbidden.
"""

#!/usr/bin/env python3
"""
Main flow with mandatory Argon2id usage for all encryption,
ensuring ephemeral keys/ciphertext are fully logged so
the secret can be rebuilt from logs alone. All references to any 'decoy' secret have been removed. Only a single real secret
is stored across shares for correct (real) answers; incorrect answers contain dummy shares.

UPDATED: Now uses Noble crypto bridge for all cryptographic operations.
"""

import os
import base64
from typing import Dict, Optional, Tuple, Union

# Logging
from modules.debug_utils import log_debug, log_crypto_event

# Noble crypto bridge
from modules.crypto_bridge import (
    argon2id,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    chacha20poly1305_encrypt,
    chacha20poly1305_decrypt,
    random_bytes
)


def derive_key_argon2id(password: str,
                        salt: bytes,
                        key_length: int = 32,
                        time_cost: int = 3,
                        memory_cost: int = 65536,
                        parallelism: int = 4,
                        ephemeral: bool = False) -> bytes:
    """
    FIXED KDF: use Argon2id via Noble bridge with exact hash_len=key_length.
    """
    ephemeral_info = {
        "salt_b64": base64.b64encode(salt).decode(),
        "ephemeral_password": password if ephemeral else "<not ephemeral>"
    }
    log_debug(
        f"Starting Argon2id KDF (Noble). pass='{password}', salt(b64)='{ephemeral_info['salt_b64']}'",
        level="INFO",
        component="CRYPTO"
    )

    # Use Noble bridge for Argon2id
    derived_bytes = argon2id(
        password=password.encode("utf-8"),
        salt=salt,
        m_cost=memory_cost,
        t=time_cost,
        p=parallelism,
        dk_len=key_length
    )

    log_crypto_event(
        operation="KDF Derive",
        algorithm="Argon2id",
        ephemeral=ephemeral,
        ephemeral_key=derived_bytes,
        argon_params={
            "time_cost": time_cost,
            "memory_cost": memory_cost,
            "parallelism": parallelism,
            "key_length": key_length
        },
        key_derived_bytes=derived_bytes,
        details={
            "message": "Argon2id (Noble) complete. Derived key is in logs.",
            "ephemeral_info": ephemeral_info
        }
    )
    return derived_bytes


def encrypt_aes256gcm(plaintext: Union[str, bytes, bytearray],
                      key: bytes,
                      aad: Optional[bytes] = None,
                      ephemeral_pass: Optional[str] = None,
                      ephemeral_salt: Optional[bytes] = None) -> Dict[str, str]:
    """
    AES-256-GCM with optional AAD binding via Noble bridge.
    Plaintext can be str, bytes, or bytearray.
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    elif isinstance(plaintext, bytearray):
        plaintext = bytes(plaintext)

    nonce = random_bytes(12)
    
    # Noble bridge returns ciphertext with tag appended
    ciphertext_with_tag = aes_gcm_encrypt(key, nonce, plaintext, aad)
    
    # Split ciphertext and tag (last 16 bytes)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    out = {
        "alg": "AES-256-GCM",
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

    details = {
        "Nonce(base64)": out["nonce"],
        "Ciphertext(base64)": out["ciphertext"],
        "Tag(base64)": out["tag"],
        "AAD_len": (len(aad) if aad else 0)
    }
    if ephemeral_pass is not None:
        details["ephemeral_password"] = ephemeral_pass
    if ephemeral_salt is not None:
        details["ephemeral_salt_b64"] = base64.b64encode(ephemeral_salt).decode()

    log_crypto_event(
        operation="Encrypt",
        algorithm="AES-256",
        mode="GCM",
        ephemeral_key=key,
        details=details,
        ephemeral=True
    )
    return out


def decrypt_aes256gcm(enc_dict: Dict[str, str], key: bytes, aad: Optional[bytes] = None) -> bytes:
    import base64
    ciphertext = base64.b64decode(enc_dict["ciphertext"])
    nonce = base64.b64decode(enc_dict["nonce"])
    tag = base64.b64decode(enc_dict["tag"])

    log_crypto_event(
        operation="Decrypt",
        algorithm="AES-256",
        mode="GCM",
        ephemeral_key=key,
        details={
            "Nonce(base64)": enc_dict["nonce"],
            "Ciphertext(base64)": enc_dict["ciphertext"],
            "Tag(base64)": enc_dict["tag"],
            "AAD_len": (len(aad) if aad else 0)
        },
        ephemeral=True
    )

    # Combine ciphertext and tag for Noble bridge
    ciphertext_with_tag = ciphertext + tag
    plaintext = aes_gcm_decrypt(key, nonce, ciphertext_with_tag, aad)
    return plaintext


def encrypt_chacha20poly1305(plaintext: Union[str, bytes, bytearray],
                             key: bytes,
                             aad: Optional[bytes] = None,
                             ephemeral_pass: Optional[str] = None,
                             ephemeral_salt: Optional[bytes] = None) -> Dict[str, str]:
    """
    ChaCha20-Poly1305 with optional AAD binding via Noble bridge.
    Returns ciphertext (includes tag) and nonce. No synthetic 'tag' field.
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    elif isinstance(plaintext, bytearray):
        plaintext = bytes(plaintext)

    nonce = random_bytes(12)
    ciphertext = chacha20poly1305_encrypt(key, nonce, plaintext, aad)

    out = {
        "alg": "ChaCha20-Poly1305",
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode()
    }
    details = {
        "Nonce(base64)": out["nonce"],
        "Ciphertext(base64)": out["ciphertext"],
        "AAD_len": (len(aad) if aad else 0)
    }
    if ephemeral_pass is not None:
        details["ephemeral_password"] = ephemeral_pass
    if ephemeral_salt is not None:
        details["ephemeral_salt_b64"] = base64.b64encode(ephemeral_salt).decode()

    log_crypto_event(
        operation="Encrypt",
        algorithm="ChaCha20-Poly1305",
        mode="Poly1305",
        ephemeral_key=key,
        details=details,
        ephemeral=True
    )
    return out


def decrypt_chacha20poly1305(enc_dict: Dict[str, str], key: bytes, aad: Optional[bytes] = None) -> bytes:
    import base64
    nonce = base64.b64decode(enc_dict["nonce"])
    ciphertext = base64.b64decode(enc_dict["ciphertext"])

    log_crypto_event(
        operation="Decrypt",
        algorithm="ChaCha20-Poly1305",
        mode="Poly1305",
        ephemeral_key=key,
        details={
            "Nonce(base64)": enc_dict["nonce"],
            "Ciphertext(base64)": enc_dict["ciphertext"],
            "AAD_len": (len(aad) if aad else 0)
        },
        ephemeral=True
    )

    plaintext = chacha20poly1305_decrypt(key, nonce, ciphertext, aad)
    return plaintext


def derive_or_recover_key(password: str,
                          salt: Optional[bytes] = None,
                          ephemeral: bool = False,
                          time_cost: int = 3,
                          memory_cost: int = 65536,
                          parallelism: int = 4) -> Tuple[bytes, bytes]:
    """
    Wrapper: generate salt if missing; derive 32-byte key using Argon2id Noble bridge.
    """
    if salt is None:
        salt = random_bytes(16)

    if ephemeral:
        log_debug(f"Using ephemeral password='{password}' (raw).", level="INFO", component="CRYPTO")
    else:
        log_debug(f"Using user-provided password='{password}' (raw).", level="INFO", component="CRYPTO")

    key = derive_key_argon2id(
        password=password,
        salt=salt,
        ephemeral=ephemeral,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism
    )
    return key, salt