#!/usr/bin/env python3
"""
recover_abc.py

Utility to reconstruct the real secret from a saved AnswerChain kit by
selecting the canonical A/B/C answers for every question.
- Loads the chosen kit JSON.
- Derives per-answer keys via Argon2id parameters stored with each entry.
- Decrypts the s0 shares (real secret path).
- Deduplicates shares by length and x-coordinate, then attempts Shamir
  reconstruction using batched combinations.
- Accepts only reconstructions that authenticate against the kit's
  final_auth entry or auth_catalog.

Prints AUTH_OK and RECOVERED_SEED_B64 when successful.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import random
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from modules.security_utils import sanitize_input, normalize_text
from modules.crypto_bridge import hkdf_sha256, hmac_sha256, consttime_equal
from modules.sss_bridge import sss_combine_batch
import CipherForge as CF

EXPECTED_QA: dict[str, list[str]] = {
    "first pet?": ["rex", "mia", "ziv"],
    "fav color?": ["tan", "cyan", "moss"],
    "birth city?": ["lima", "riga", "oslo"],
    "first car?": ["saab", "vw", "ford"],
    "lucky number?": ["7", "13", "21"],
    "childhood toy?": ["kite", "lego", "yo-yo"],
    "school mascot?": ["wolf", "shark", "falcon"],
    "street lived?": ["elm", "oak", "pine"],
    "mother mid name?": ["ann", "mae", "lyn"],
    "best friend?": ["max", "zoe", "arun"],
    "dream job?": ["pilot", "chef", "coder"],
    "first concert?": ["abba", "muse", "blur"],
    "fav fruit?": ["fig", "pear", "plum"],
    "secret hobby?": ["ski", "bake", "chess"],
}



_DTE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-="


def _dte_bucket_for_len(n: int) -> int:
    for edge in (64, 96, 128, 192, 256, 384, 512):
        if n <= edge:
            return edge
    return 512

def _norm(s: str) -> str:
    return sanitize_input(normalize_text(s))


def _alt_hash(text: str) -> str:
    return hashlib.sha3_256(_norm(text).encode("utf-8")).hexdigest()


def _q_integrity_hash(q_text: str, alts: list[str]) -> str:
    block = _norm(q_text) + "\n" + "\n".join(sorted(_norm(a) for a in alts))
    return hashlib.sha3_256(block.encode("utf-8")).hexdigest()


def _aad_bytes(q_hash: str, alt_hash: str, algorithm: str, version: int) -> bytes:
    return f"{q_hash}|{alt_hash}|{algorithm}|{version}".encode("utf-8")


def _auth_ok(cfg: dict, seed_bytes: bytes) -> bool:
    fa = cfg.get("final_auth")
    if isinstance(fa, dict):
        try:
            salt = base64.b64decode(fa.get("salt", ""))
            expected = base64.b64decode(fa.get("hmac_sha256", ""))
            key = hkdf_sha256(seed_bytes, salt, b"SECQ final-auth v3", 32)
            tag = hmac_sha256(key, seed_bytes)
            if consttime_equal(tag, expected):
                return True
        except Exception:
            pass
    for entry in cfg.get("auth_catalog") or []:
        try:
            salt = base64.b64decode(entry.get("salt", ""))
            expected = base64.b64decode(entry.get("hmac_sha256", ""))
            key = hkdf_sha256(seed_bytes, salt, b"SECQ final-auth v3", 32)
            tag = hmac_sha256(key, seed_bytes)
            if consttime_equal(tag, expected):
                return True
        except Exception:
            continue
    return False


def _dte_meta_from_b64(seed_b64: str | None) -> dict:
    if not seed_b64:
        return {}
    try:
        packed = base64.b64decode(seed_b64.encode("utf-8"), validate=True)
        meta_b = packed[32:]
        return json.loads(meta_b.decode("utf-8")) if meta_b else {}
    except Exception:
        return {}


def _dte_decode_b64(seed_b64: str) -> str:
    try:
        packed = base64.b64decode(seed_b64.encode("ascii"))
    except Exception:
        packed = b""
    seed, meta = (packed[:32], packed[32:]) if len(packed) > 32 else (packed, b"")
    try:
        m = json.loads(meta.decode("utf-8")) if meta else {}
        if isinstance(m, dict) and m.get("plain_b64"):
            try:
                return base64.b64decode(m.get("plain_b64")).decode("utf-8")
            except Exception:
                pass
        exp_len = int(m.get("len", 0))
        exp_chk = str(m.get("chk", ""))
        rng = random.SystemRandom(int.from_bytes(hashlib.sha3_256(seed).digest(), "big"))
        cand = "".join(rng.choice(_DTE_ALPHABET) for _ in range(max(1, exp_len)))
        if exp_len > 0 and hashlib.sha3_256(cand.encode("utf-8")).hexdigest()[:16] == exp_chk:
            return cand
        target_len = _dte_bucket_for_len(exp_len) if exp_len else _dte_bucket_for_len(96)
    except Exception:
        target_len = _dte_bucket_for_len(96)
    rng = random.SystemRandom(int.from_bytes(hashlib.sha3_256(seed or b"DTE").digest(), "big"))
    return "".join(rng.choice(_DTE_ALPHABET) for _ in range(target_len))


def _correct_picks_for_question(q_text: str, alts: list[str]) -> list[str]:
    qn = _norm(q_text)
    expected = EXPECTED_QA.get(qn) or EXPECTED_QA.get(q_text.strip().lower())
    if not expected:
        return alts[:3]
    norm_to_alt = {_norm(a): a for a in alts}
    picks: list[str] = []
    for ans in expected:
        target = ans
        for norm_alt, original in norm_to_alt.items():
            if norm_alt == target:
                picks.append(original)
                break
        else:
            return alts[:3]
    return picks


def _derive_key(entry: dict, plaintext_hint: str, version: int, q_hash: str, alt_hash: str) -> tuple[bytes, bytes, str]:
    salt_b64 = entry.get("salt") or entry.get("salt_b64")
    if not salt_b64:
        raise ValueError("missing salt")
    salt = base64.b64decode(salt_b64)
    kdf = entry.get("kdf") or {}
    tt = int(kdf.get("t", 1))
    mm = int(kdf.get("m", 1024))
    pp = int(kdf.get("p", 1))
    key, _ = CF.derive_or_recover_key(_norm(plaintext_hint), salt, False, tt, mm, pp)
    alg = entry.get("algorithm") or "aes256gcm"
    aad = _aad_bytes(q_hash, alt_hash, alg, version)
    return key, aad, alg


def _decrypt_share(entry: dict, alt_text: str, q_hash: str, alt_hash: str, version: int) -> bytes | None:
    try:
        key, aad, alg = _derive_key(entry, alt_text, version, q_hash, alt_hash)
        if alg == "chacha20poly1305":
            return CF.decrypt_chacha20poly1305(entry, key, aad=aad)
        if alg == "xchacha20poly1305" and hasattr(CF, "decrypt_xchacha20poly1305"):
            return CF.decrypt_xchacha20poly1305(entry, key, aad=aad)
        if alg == "aes256gcm_siv" and hasattr(CF, "decrypt_aes256gcm_siv"):
            return CF.decrypt_aes256gcm_siv(entry, key, aad=aad)
        return CF.decrypt_aes256gcm(entry, key, aad=aad)
    except Exception:
        return None


def _dedupe_by_x(shares: Iterable[bytes]) -> list[bytes]:
    unique: dict[tuple[int, int], bytes] = {}
    for share in shares:
        if not share:
            continue
        key = (len(share), share[-1])
        unique[key] = share
    return list(unique.values())


def _try_combine(shares: list[bytes], threshold: int, cfg: dict) -> str | None:
    if len(shares) < threshold:
        return None

    def window_subsets() -> list[tuple[int, ...]]:
        subsets: list[tuple[int, ...]] = []
        for start in range(0, len(shares) - threshold + 1):
            subsets.append(tuple(range(start, start + threshold)))
        return subsets

    subsets = window_subsets()
    if not subsets:
        subsets = [tuple(range(threshold))]

    tested = set(subsets)

    def evaluate_batch(batch: list[tuple[int, ...]]) -> str | None:
        if not batch:
            return None
        results = asyncio.run(sss_combine_batch(shares, batch))
        for combined in results:
            if combined is None:
                continue
            base64_candidate = _extract_b64(combined)
            if not base64_candidate:
                continue
            try:
                seed_bytes = base64.b64decode(base64_candidate.encode("utf-8"), validate=True)
            except Exception:
                continue
            if _auth_ok(cfg, seed_bytes):
                return base64_candidate
        return None

    candidate = evaluate_batch(subsets)
    if candidate:
        return candidate

    budget = 50000
    random_needed = max(0, budget - len(subsets))
    indices = list(range(len(shares)))
    for _ in range(random_needed):
        subset = tuple(sorted(random.sample(indices, threshold)))
        if subset in tested:
            continue
        tested.add(subset)
        candidate = evaluate_batch([subset])
        if candidate:
            return candidate
    return None


def _extract_b64(combined: bytes) -> str | None:
    try:
        candidate = combined.decode("utf-8")
        base64.b64decode(candidate.encode("utf-8"), validate=True)
        return candidate
    except Exception:
        pass
    try:
        payload = combined[2:] if len(combined) >= 2 else combined
        payload = payload.rstrip(b"")
        candidate = payload.decode("ascii")
        base64.b64decode(candidate.encode("utf-8"), validate=True)
        return candidate
    except Exception:
        return None


def _collect_real_shares(questions, enc_shares, version: int) -> list[bytes]:
    partials: list[bytes] = []
    for q in questions:
        q_text = q.get("text", "")
        alts = q.get("alternatives", [])
        q_hash = q.get("integrity_hash") or _q_integrity_hash(q_text, alts)
        picks = _correct_picks_for_question(q_text, alts)
        for alt in picks:
            a_hash = _alt_hash(alt)
            entry = (enc_shares.get(q_hash) or {}).get(a_hash, {}).get("s0")
            if not entry:
                continue
            share = _decrypt_share(entry, alt, q_hash, a_hash, version)
            if share is not None:
                partials.append(share)
    return partials


def main() -> int:
    if len(sys.argv) > 1:
        kit_path = Path(sys.argv[1]).resolve()
    else:
        default_dir = SRC / "user_configured_security_questions"
        files = sorted(p for p in default_dir.glob("*.json") if p.is_file())
        if not files:
            print("ERROR: no kit files found in", default_dir)
            return 1
        for idx, file in enumerate(files, 1):
            print(f" {idx}. {file.name}")
        while True:
            try:
                choice = int(input("Choice: ").strip())
                if 1 <= choice <= len(files):
                    kit_path = files[choice - 1]
                    break
            except Exception:
                pass
            print("Invalid selection")
    if not kit_path.exists():
        print("ERROR: kit not found at", kit_path)
        return 1

    try:
        data = json.loads(kit_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print("ERROR: failed to parse kit JSON:", exc)
        return 1

    cfg = data.get("config") or {}
    questions = data.get("questions") or []
    enc_shares = data.get("encrypted_shares") or {}
    threshold = int(cfg.get("real_threshold", 0))
    version = int(cfg.get("version", 3))

    if not questions or not enc_shares or threshold <= 0:
        print("ERROR: kit missing required sections or invalid threshold")
        return 1

    print(f"KIT: {kit_path}")
    print(f"Threshold T={threshold}, questions={len(questions)}")

    partials = _collect_real_shares(questions, enc_shares, version)
    if not partials:
        print("ERROR: no shares decrypted for the expected answers")
        return 2

    unique_shares = _dedupe_by_x(partials)
    print(f"Decrypted shares: total={len(partials)}, unique_by_x={len(unique_shares)}, share_len={len(unique_shares[0]) if unique_shares else 'n/a'}")

    recovered_b64 = _try_combine(unique_shares, threshold, cfg)
    if not recovered_b64:
        print('AUTH_OK=False')
        print('RECOVERED_SEED_B64=')
        print('Secret: Failed to recover secret')
        return 4

    print('AUTH_OK=True')
    print('RECOVERED_SEED_B64=', recovered_b64)
    try:
        meta = _dte_meta_from_b64(recovered_b64)
        print('Secret:', 'Verified')
        decoded = _dte_decode_b64(recovered_b64)
        print('Decoded Secret:', decoded)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
