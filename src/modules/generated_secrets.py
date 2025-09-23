#!/usr/bin/env python3
"""
generated_secrets.py

Deterministic generation of fake secrets for incorrect answer combinations.
Ensures indistinguishability between real and generated secrets through:
- Deterministic derivation using HMAC
- Constant-time operations
- Identical format and structure
- No timing or format oracles
"""

import base64
import hashlib
import hmac
import json
import struct
from typing import Dict, List, Tuple, Optional, Any

from modules.crypto_bridge import (
    hkdf_sha256,
    hmac_sha256,
    consttime_equal
)
from modules.debug_utils import log_debug, log_error

def derive_kit_identifier(kit: Dict[str, Any]) -> bytes:
    '''Derive a deterministic identifier for a recovery kit.'''
    mapping = kit if isinstance(kit, dict) else {}
    cfg_candidate = mapping.get("config") if isinstance(mapping, dict) else None
    cfg = cfg_candidate if isinstance(cfg_candidate, dict) else {}
    questions = mapping.get("questions") if isinstance(mapping, dict) and isinstance(mapping.get("questions"), list) else []
    metadata = mapping.get("metadata") if isinstance(mapping, dict) and isinstance(mapping.get("metadata"), dict) else {}
    anchor = {"config": cfg, "questions": questions, "metadata": metadata}
    try:
        canonical = json.dumps(anchor, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        log_error(
            "Failed to canonicalize kit for identifier derivation.",
            details={"error": str(exc)}
        )
        canonical = json.dumps({"fallback": True}, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    digest = hashlib.sha3_256(canonical.encode('utf-8')).digest()
    try:
        question_count = len(questions)
    except TypeError:
        question_count = 0
    log_debug(
        "Derived kit identifier",
        level="DEBUG",
        component="GENERATOR",
        details={
            "kit_id_prefix": digest.hex()[:16],
            "question_count": question_count,
            "has_final_auth": bool(cfg.get("final_auth"))
        }
    )
    return digest

class DeterministicSecretGenerator:
    """Generate deterministic fake secrets that are indistinguishable from real ones."""
    
    @classmethod
    def from_kit(cls, kit: Dict[str, Any]) -> "DeterministicSecretGenerator":
        '''Create a generator instance from a recovery kit mapping.'''
        mapping = kit if isinstance(kit, dict) else {}
        kit_id = derive_kit_identifier(mapping)
        cfg_candidate = mapping.get("config") if isinstance(mapping, dict) else None
        cfg = cfg_candidate if isinstance(cfg_candidate, dict) else {}
        raw_kmap = None
        if isinstance(cfg, dict):
            raw_kmap = cfg.get("k_map_b64") or cfg.get("k_map")
        k_map_bytes: Optional[bytes] = None
        if isinstance(raw_kmap, str):
            try:
                k_map_bytes = base64.b64decode(raw_kmap.encode("ascii"), validate=True)
            except Exception as exc:
                log_error(
                    "Invalid k_map encoding in kit config.",
                    details={"error": str(exc)}
                )
                k_map_bytes = None
        generator = cls(kit_id, k_map=k_map_bytes)
        log_debug(
            "Deterministic generator created from kit.",
            level="DEBUG",
            component="GENERATOR",
            details={
                "kit_id_prefix": kit_id.hex()[:16],
                "k_map_provided": bool(k_map_bytes)
            }
        )
        return generator

    def __init__(self, kit_id: bytes, k_map: bytes = None):
        """
        Initialize generator with kit-specific parameters.
        
        Args:
            kit_id: Unique kit identifier
            k_map: Master key for this kit (generated at kit creation)
        """
        self.kit_id = kit_id
        # If k_map not provided, derive from kit_id (for recovery mode)
        self.k_map = k_map if k_map else hkdf_sha256(
            kit_id, 
            b"KIT_MAP_KEY",
            b"SECQ_deterministic_v1",
            32
        )
        self.k_ver = hkdf_sha256(self.k_map, b"", b"verification_key_v1", 32)
        
    def canonicalize_answers(self, answers: List[Tuple[str, str]]) -> bytes:
        '''
        Convert answer selections to canonical fixed-width bitmap.

        Args:
            answers: List of (question_hash, alternative_hash) tuples

        Returns:
            Canonical representation of answers
        '''
        sanitized: List[Tuple[str, str]] = []
        if answers:
            for q_hash, a_hash in answers:
                sanitized.append((str(q_hash), str(a_hash)))
        unique_sorted = sorted(set(sanitized))
        answer_repr = json.dumps(unique_sorted, sort_keys=True, separators=(',', ':'))
        canonical = hashlib.sha3_256(answer_repr.encode('utf-8')).digest()
        log_debug(
            "Canonicalized answers",
            level="DEBUG",
            component="GENERATOR",
            details={
                "answer_count": len(answers) if answers else 0,
                "unique_count": len(unique_sorted),
                "canonical_hash": canonical.hex()
            }
        )
        return canonical

    def generate_deterministic_secret(self, answers: List[Tuple[str, str]], 
                                     expected_format: Dict[str, Any] = None) -> str:
        """
        Generate a deterministic fake secret from answer combination.
        
        Args:
            answers: Selected answer pairs
            expected_format: Format specification (length, charset, etc.)
            
        Returns:
            Base64-encoded secret matching real secret format exactly
        """
        # Canonicalize answer set - even empty answers produce deterministic output
        canonical_answers = self.canonicalize_answers(answers) if answers else b'\x00' * 32
        
        # Deterministic signature
        sig_a = hmac.new(
            self.k_map,
            self.kit_id + b'||' + canonical_answers,
            hashlib.sha256
        ).digest()
        
        # Generate 32-byte secret matching real secret format
        secret_bytes = hkdf_sha256(
            sig_a,
            self.kit_id,
            b"GENERATED_SECRET_v1",
            32  # Standard 32-byte secret size
        )
        
        # Create DTE v2 format matching real secrets exactly
        # Real secrets use: 32-byte seed + metadata JSON
        meta = {
            "v": 2,
            "len": 32,
            "chk": hashlib.sha3_256(secret_bytes).hexdigest()[:16],
            "plain_b64": base64.b64encode(secret_bytes).decode("ascii")
        }
        
        # Pack as: seed[32] + json_meta
        packed = secret_bytes + json.dumps(meta, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        
        # Return base64 of packed data
        secret_b64 = base64.b64encode(packed).decode('ascii')
        
        log_debug(
            "Generated deterministic secret",
            level="INFO", 
            component="GENERATOR",
            details={
                "sig_a": sig_a.hex()[:16],
                "secret_bytes_len": len(secret_bytes),
                "packed_len": len(packed),
                "b64_len": len(secret_b64),
                "answers_provided": len(answers) if answers else 0
            }
        )
        
        return secret_b64
        
    def _generate_believable_secret_text(self, seed: bytes, 
                                        format_spec: Dict[str, Any] = None) -> str:
        """
        Generate believable secret text that looks like a real password/key.
        
        Args:
            seed: Deterministic seed bytes
            format_spec: Optional format specification
            
        Returns:
            Believable secret text
        """
        # Derive components deterministically from seed
        prng_seed = int.from_bytes(seed[:8], 'big')
        
        # Character sets for believable secrets
        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lowercase = "abcdefghijklmnopqrstuvwxyz"
        digits = "0123456789"
        symbols = "!@#$%^&*-_=+"
        
        # Build deterministic but random-looking secret
        secret_parts = []
        
        # Generate word-like segments
        for i in range(3):
            segment_seed = prng_seed + i
            
            # Start with uppercase
            idx1 = segment_seed % len(uppercase)
            secret_parts.append(uppercase[idx1])
            
            # Add lowercase letters
            for j in range(3):
                idx2 = (segment_seed * (j + 2)) % len(lowercase)
                secret_parts.append(lowercase[idx2])
            
            # Add digit
            idx3 = (segment_seed * 7) % len(digits)
            secret_parts.append(digits[idx3])
            
            if i < 2:  # Add separator between segments
                idx4 = (segment_seed * 13) % len(symbols)
                secret_parts.append(symbols[idx4])
        
        # Add final complexity
        final_seed = prng_seed * 31
        for k in range(4):
            idx5 = (final_seed * (k + 1)) % len(uppercase)
            secret_parts.append(uppercase[idx5])
            idx6 = (final_seed * (k + 2)) % len(digits)
            secret_parts.append(digits[idx6])
        
        secret_text = ''.join(secret_parts)
        
        # Ensure minimum length
        if len(secret_text) < 24:
            # Pad with deterministic pattern
            padding_seed = int.from_bytes(seed[8:16], 'big')
            while len(secret_text) < 24:
                charset = uppercase + lowercase + digits
                idx = padding_seed % len(charset)
                secret_text += charset[idx]
                padding_seed = (padding_seed * 17) % (2**32)
        
        return secret_text
        
    def _encode_with_dte_v2(self, secret_text: str) -> str:
        """
        Encode secret text using DTE v2 format (matching real secrets).
        
        Args:
            secret_text: Plain text secret
            
        Returns:
            Base64-encoded DTE v2 format
        """
        # Convert text to bytes
        secret_bytes = secret_text.encode('utf-8')
        
        # Generate deterministic seed (32 bytes)
        seed = hkdf_sha256(
            self.k_map,
            secret_bytes,
            b"DTE_SEED_v2",
            32
        )
        
        # Create DTE v2 metadata
        meta = {
            "v": 2,  # Version 2 for compatibility
            "t": "text",  # Text type
            "l": len(secret_bytes),  # Length
            "c": hashlib.sha256(secret_bytes).hexdigest()[:8]  # Checksum
        }
        
        # Pack as DTE v2 format: seed + encrypted_data + metadata
        # For fake secrets, we'll use a simpler approach
        # Real DTE would encrypt, but we'll create a believable structure
        
        # Simulate encrypted data (deterministic from seed)
        encrypted_sim = hkdf_sha256(
            seed,
            secret_bytes,
            b"DTE_ENC_SIM",
            len(secret_bytes)
        )
        
        # XOR for simple obfuscation (deterministic)
        obfuscated = bytes(a ^ b for a, b in zip(secret_bytes, encrypted_sim))
        
        # Pack structure
        packed_data = seed + obfuscated + json.dumps(meta).encode('utf-8')
        
        # Base64 encode
        b64_encoded = base64.b64encode(packed_data).decode('ascii')
        
        return b64_encoded
        
    def _apply_dte_encoding(self, secret_bytes: bytes, 
                           format_spec: Dict[str, Any] = None) -> str:
        """
        Apply DTE-compatible encoding for format consistency.
        DEPRECATED - Use _encode_with_dte_v2 instead
        """
        # Generate text from bytes first
        secret_text = self._generate_believable_secret_text(secret_bytes, format_spec)
        return self._encode_with_dte_v2(secret_text)
        
    def _generate_verification(self, secret_bytes: bytes) -> str:
        """
        Generate verification field identical to real secrets.
        
        Args:
            secret_bytes: Secret to verify
            
        Returns:
            Verification hash
        """
        ver_input = secret_bytes + self.kit_id + b"v1"
        ver = hmac.new(self.k_ver, ver_input, hashlib.sha256).hexdigest()
        return ver
        
    def validate_generation_determinism(self, answers: List[Tuple[str, str]], 
                                       iterations: int = 10) -> bool:
        """
        Verify that generation is fully deterministic.
        
        Args:
            answers: Answer set to test
            iterations: Number of iterations to verify
            
        Returns:
            True if all generations are identical
        """
        first_result = None
        
        for i in range(iterations):
            result = self.generate_deterministic_secret(answers)
            
            if first_result is None:
                first_result = result
            elif not consttime_equal(result.encode(), first_result.encode()):
                log_error(
                    "Non-deterministic generation detected!",
                    details={"iteration": i, "mismatch": True}
                )
                return False
                
        log_debug(
            "Generation determinism verified",
            level="INFO",
            component="GENERATOR",
            details={"iterations": iterations, "deterministic": True}
        )
        
        return True


class SecretResponseNormalizer:
    """Ensure identical response structure for real and generated secrets."""
    
    @staticmethod
    def normalize_response(secret_b64: str, is_real: bool, 
                          kit_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create normalized response structure.
        
        Args:
            secret_b64: The secret (real or generated)
            is_real: Whether this is the real secret (for logging only)
            kit_metadata: Kit configuration metadata
            
        Returns:
            Normalized response dict
        """
        # Standard response structure
        response = {
            "status": "complete",
            "result": secret_b64,
            "kit_version": kit_metadata.get("version", 3),
            "algorithm": kit_metadata.get("algorithm", "aes256gcm")
        }
        
        # Log full details in beta mode
        log_debug(
            "Secret response normalized",
            level="DEBUG",
            component="NORMALIZER",
            details={
                "is_real": is_real,
                "secret_b64": secret_b64[:50] + "..." if len(secret_b64) > 50 else secret_b64,
                "kit_version": response["kit_version"],
                "algorithm": response["algorithm"]
            }
        )
        
        return response
        
    @staticmethod
    def add_timing_jitter(base_delay_ms: float = 100.0) -> None:
        """
        Add controlled timing jitter to prevent timing analysis.
        
        Args:
            base_delay_ms: Base delay in milliseconds
        """
        import time
        import secrets
        
        # Deterministic jitter range
        jitter = (secrets.randbits(8) / 255.0) * 50  # 0-50ms jitter
        total_delay = (base_delay_ms + jitter) / 1000.0
        
        time.sleep(total_delay)
        
        log_debug(
            "Timing jitter applied",
            level="DEBUG", 
            component="NORMALIZER",
            details={"base_ms": base_delay_ms, "jitter_ms": jitter}
        )
