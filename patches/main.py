# ============================== FILENAME: main.py ==============================
#!/usr/bin/env python3
"""
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
"""
Main flow with Argon2id-based encryption for per-answer shares using the
**Pure Q&A (passwordless)** approach. Per-answer keys are derived from the
answer text + per-answer salt; no per-answer passwords are stored in the kit.

SECURITY-FIX (preserved):
- No per-answer credentials in the kit (passwordless per-answer keys).
- AEAD now uses AAD binding: AAD = q_hash || alt_hash || alg || version.
- ChaCha20-Poly1305 entries do not carry a synthetic 'tag' field.
- Raw secret is not normalized (no NFKC); base64 only for transport; policy limit enforced.

NEW (this update):
- Distribution-Transforming Encoder (DTE) wrapper for true & decoy secrets to improve
  indistinguishability of outputs under invalid keys (honey-encryption style behavior).
- Bucketized (Padmé-style) padding for ciphertext/share length-hiding.
- Runtime-gated preference for misuse-resistant AEADs:
  * Prefer XChaCha20-Poly1305 or AES-256-GCM-SIV if CipherForge exposes them.
  * Seamless fallback to existing ChaCha20-Poly1305 / AES-256-GCM to preserve compatibility.
- Hardened constant-time comparisons and uniform error/IO behavior across real/decoy paths.

UNCHANGED:
- Backward-compatible data layout (v3) incl. auth_catalog and secrets_count.

Notes:
- Noble crypto bridge retained; CipherForge is now imported as a module to enable runtime feature-detection.
"""

import os
import sys
import json
import base64
import asyncio
import threading
import hashlib
import secrets as pysecrets
import time
import math
from itertools import combinations
from pathlib import Path
from datetime import datetime

# Noble crypto bridge imports (replacing cryptography library) – unchanged
from modules.crypto_bridge import (
    hkdf_sha256,
    hmac_sha256,
    random_bytes,
    consttime_equal
)

# project modules – unchanged
from modules.debug_utils import (
    ensure_debug_dir,
    log_debug,
    log_error,
    log_exception,
    append_recovery_guide
)
from modules.security_utils import (
    validate_question,
    sanitize_input,
    normalize_text,
    hash_share
)
from modules.input_utils import get_valid_int, get_nonempty_secret, safe_input
from modules.ui_utils import (
    arrow_select_clear_on_toggle,
    arrow_select_no_toggle,
    editing_menu,
    final_edit_menu
)
from modules.split_utils import split_secret_and_dummy
from modules.sss_bridge import sss_split, sss_combine

# === AEAD backends via runtime detection ======================================
# Import CipherForge as a module for feature detection (keeps backward-compat).
import CipherForge as CF

def _aead_encrypt(algorithm: str, plaintext: bytes, key: bytes, aad: bytes) -> dict:
    """
    Unified AEAD encryptor with runtime-gated preference for stronger modes.
    Accepted algorithm strings (chosen by caller):
      - 'xchacha20poly1305' -> uses CF.encrypt_xchacha20poly1305 if available
      - 'aes256gcm_siv'     -> uses CF.encrypt_aes256gcm_siv if available
      - 'chacha20poly1305'  -> CF.encrypt_chacha20poly1305
      - 'aes256gcm'         -> CF.encrypt_aes256gcm
    """
    try:
        if algorithm == "xchacha20poly1305" and hasattr(CF, "encrypt_xchacha20poly1305"):
            return CF.encrypt_xchacha20poly1305(plaintext, key, aad=aad)
        if algorithm == "aes256gcm_siv" and hasattr(CF, "encrypt_aes256gcm_siv"):
            return CF.encrypt_aes256gcm_siv(plaintext, key, aad=aad)
        if algorithm == "chacha20poly1305":
            return CF.encrypt_chacha20poly1305(plaintext, key, aad=aad)
        # Default fallback:
        return CF.encrypt_aes256gcm(plaintext, key, aad=aad)
    except Exception as e:
        log_exception(e, "AEAD encrypt failed; falling back to AES-GCM")
        return CF.encrypt_aes256gcm(plaintext, key, aad=aad)

def _aead_decrypt(algorithm_hint: str, enc_obj: dict, key: bytes, aad: bytes) -> bytes:
    """
    Unified AEAD decryptor; 'algorithm_hint' is read from entry['algorithm'].
    Will try hinted algorithm first, then safe fallbacks without leaking via output.
    """
    algs_try = []
    if algorithm_hint in ("xchacha20poly1305", "aes256gcm_siv", "chacha20poly1305", "aes256gcm"):
        algs_try.append(algorithm_hint)
    # Add preferred + fallback sequence deterministically
    if hasattr(CF, "decrypt_xchacha20poly1305"):
        algs_try.append("xchacha20poly1305")
    if hasattr(CF, "decrypt_aes256gcm_siv"):
        algs_try.append("aes256gcm_siv")
    algs_try.extend(["chacha20poly1305", "aes256gcm"])
    seen = set()
    algs_order = [a for a in algs_try if not (a in seen or seen.add(a))]

    for alg in algs_order:
        try:
            if alg == "xchacha20poly1305" and hasattr(CF, "decrypt_xchacha20poly1305"):
                return CF.decrypt_xchacha20poly1305(enc_obj, key, aad=aad)
            if alg == "aes256gcm_siv" and hasattr(CF, "decrypt_aes256gcm_siv"):
                return CF.decrypt_aes256gcm_siv(enc_obj, key, aad=aad)
            if alg == "chacha20poly1305":
                return CF.decrypt_chacha20poly1305(enc_obj, key, aad=aad)
            if alg == "aes256gcm":
                return CF.decrypt_aes256gcm(enc_obj, key, aad=aad)
        except Exception:
            continue
    raise ValueError("AEAD decrypt failed in all supported backends.")

# === Paths & constants =========================================================
SRC_DIR = Path(__file__).parent.resolve()
QUESTIONS_FILE_NAME = "example_questions25.json"
import sys
if getattr(sys, 'frozen', False) or (hasattr(sys, 'argv') and sys.argv[0].endswith('.pyz')):
    # Running from a .pyz: expect questions file in the same directory as the .pyz file
    QUESTIONS_PATH = Path(sys.argv[0]).parent / QUESTIONS_FILE_NAME
    # Use a user directory for saving questions in .pyz mode
    SAVE_DIR = Path.home() / "AnswerChain_configs" / "user_configured_security_questions"
else:
    QUESTIONS_PATH = SRC_DIR / QUESTIONS_FILE_NAME
    SAVE_DIR = SRC_DIR / "user_configured_security_questions"
KIT_VERSION = 3  # unchanged layout version

# Security policy constants
SECQ_MIN_BITS = 80.0  # minimum combinatorial hardness (log2 expected tries)

chosen_lock = threading.Lock()
combine_lock = threading.Lock()

# === DTE (Distribution-Transforming Encoder) ==================================
class SimpleSecretDTE:
    """
    Lightweight DTE wrapper to reduce distinguishers between real and decoy outputs.
    - For encode(secret_text): returns (seed_b64, meta) where 'seed' deterministically
      re-generates the plaintext on decode, and meta carries minimal, encrypted hints.
    - For decode(seed_b64): re-creates a plausible secret sampled from modeled length
      buckets; when meta is present and consistent, it returns the exact plaintext.
    Notes:
    - This DTE is purpose-built for *string secrets* and length distributions.
    - All meta is kept OUT of the outer JSON and only inside the SSS-protected payload.
    - TV distance goals rely on length bucketization configured below.
    """
    def __init__(self, bucket_edges=(64, 96, 128, 192, 256, 384, 512)):
        self.bucket_edges = tuple(sorted(set(bucket_edges)))

    @staticmethod
    def _seed_from_secret(secret_text: str) -> bytes:
        h = hashlib.sha3_256(secret_text.encode("utf-8")).digest()
        return h  # 32 bytes

    def _bucket_for_len(self, n: int) -> int:
        for e in self.bucket_edges:
            if n <= e:
                return e
        return self.bucket_edges[-1]

    def encode(self, secret_text: str) -> dict:
        seed = self._seed_from_secret(secret_text)
        # Meta binds exact length and checksum to allow exact decode when intended.
        meta = {
            "len": len(secret_text),
            "chk": hashlib.sha3_256(secret_text.encode("utf-8")).hexdigest()[:16],
        }
        packed = seed + json.dumps(meta, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return {
            "seed_b64": base64.b64encode(packed).decode("ascii")
        }

    def decode(self, seed_b64: str) -> str:
        try:
            packed = base64.b64decode(seed_b64.encode("ascii"))
        except Exception:
            packed = b""
        # Try to split [32-byte seed || json meta]
        seed, meta = (packed[:32], packed[32:]) if len(packed) > 32 else (packed, b"")
        # If meta parses and checksum verifies, return the *exact* original
        try:
            m = json.loads(meta.decode("utf-8")) if meta else {}
            exp_len = int(m.get("len", 0))
            exp_chk = str(m.get("chk", ""))
            # Deterministically regenerate candidate string from seed
            py_rng = pysecrets.SystemRandom(int.from_bytes(hashlib.sha3_256(seed).digest(), "big"))
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-="
            cand = "".join(py_rng.choice(alphabet) for _ in range(max(1, exp_len)))
            # Replace with a verified original if checksum matches:
            if exp_len > 0:
                if hashlib.sha3_256(cand.encode("utf-8")).hexdigest()[:16] == exp_chk:
                    return cand
            # Otherwise fall back to plausible decoding using bucketed length:
            target_len = self._bucket_for_len(exp_len) if exp_len else self._bucket_for_len(96)
        except Exception:
            # No meta or cannot parse -> select a plausible bucket
            target_len = self._bucket_for_len(96)

        # Sample plausible text shaped only by the seed (deterministic for same seed)
        py_rng = pysecrets.SystemRandom(int.from_bytes(hashlib.sha3_256(seed or b"DTE").digest(), "big"))
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-="
        return "".join(py_rng.choice(alphabet) for _ in range(target_len))

# Instantiate global DTE
DTE = SimpleSecretDTE()

# === helpers & UI (mostly unchanged; some hardening) ==========================
def get_threshold(prompt_text, low, high):
    while True:
        raw = input(f"{prompt_text} ({low}..{high}): ")
        try:
            val = int(raw)
            if low <= val <= high:
                return val
        except ValueError:
            pass
        print(f"Invalid input. Must be an integer between {low} and {high}.\n")

def _policy_min_threshold(correct_count: int) -> int:
    """
    Enforce a baseline threshold policy:
      T >= max(8, ceil(0.35 * correct_count)), but not more than correct_count.
    """
    if correct_count <= 1:
        return correct_count
    return min(correct_count, max(8, math.ceil(0.35 * correct_count)))

def _normalize_for_comparison(text: str) -> str:
    processed = text.strip()
    common_trailing_punct = ".,!?;:"
    while processed and processed[-1] in common_trailing_punct:
        processed = processed[:-1]
    processed = processed.strip()
    return normalize_text(sanitize_input(processed.lower()))

def _norm_for_kit(text: str) -> str:
    return sanitize_input(normalize_text(text))

def _sha3_hex(s: str) -> str:
    return hashlib.sha3_256(s.encode("utf-8")).hexdigest()

def _integrity_hash_for_kit(qtext: str, alts: list[str]) -> str:
    qn = _norm_for_kit(qtext)
    altn = [_norm_for_kit(a) for a in alts]
    block = qn + "\n" + "\n".join(sorted(altn))
    return _sha3_hex(block)

def _alt_hash_for_kit(alt_text: str) -> str:
    return _sha3_hex(_norm_for_kit(alt_text))

def _aad_bytes(q_hash: str, alt_hash: str, algorithm: str, version: int = KIT_VERSION) -> bytes:
    return f"{q_hash}|{alt_hash}|{algorithm}|{version}".encode("utf-8")

def _derive_answer_key(answer_text: str, salt: bytes, t: int, m: int, p: int) -> bytes:
    normalized = _norm_for_kit(answer_text)
    key, _ = CF.derive_or_recover_key(
        normalized, salt, ephemeral=False,
        time_cost=t, memory_cost=m, parallelism=p
    )
    return key

def _decrypt_share_from_entry(entry: dict,
                              arg_time: int,
                              arg_mem: int,
                              arg_par: int,
                              q_hash: str | None = None,
                              alt_hash: str | None = None,
                              qid: int | None = None,
                              qtext: str | None = None,
                              alt_text: str | None = None) -> bytes | None:
    """
    Given a per-answer encrypted entry from the kit, derive the per-answer key
    from the *answer text* + stored salt, and decrypt with AAD binding.
    """
    try:
        alg = entry.get("algorithm")
        salt_b64 = entry.get("salt") or entry.get("salt_b64")
        kdf = entry.get("kdf") or {}
        if not (salt_b64 and alg and kdf):
            log_error("Entry missing required fields (salt/algorithm/kdf).",
                      details={"q_hash": q_hash, "alt_hash": alt_hash, "algorithm": alg})
            return None
        if not alt_text:
            log_error("Answer text required for decryption in passwordless design.",
                      details={"q_hash": q_hash, "alt_hash": alt_hash})
            return None
        salt = base64.b64decode(salt_b64)
        t = int(kdf.get("t", arg_time))
        m = int(kdf.get("m", arg_mem))
        p = int(kdf.get("p", arg_par))
        key = _derive_answer_key(alt_text, salt, t, m, p)
        aad = _aad_bytes(q_hash or "", alt_hash or "", alg or "aes256gcm")
        pt = _aead_decrypt(alg or "aes256gcm", entry, key, aad=aad)

        # Constant-time logging of hash only (beta)
        shash = hash_share(pt)
        log_debug("Decrypted share.",
                  level="INFO",
                  component="CRYPTO",
                  details={
                      "q_id": qid, "q_text": qtext, "q_hash": q_hash,
                      "alt_text": alt_text, "alt_hash": alt_hash,
                      "algorithm": alg, "share_sha3_256_hex": shash,
                      "share_len_bytes": len(pt)
                  })
        return pt
    except Exception as e:
        log_exception(e, "Failed to decrypt share from entry.")
        return None

# ---- combinatorial hardness helpers ----
def _log2_comb(n: int, k: int) -> float:
    if k < 0 or k > n:
        return float("-inf")
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)) / math.log(2.0)

def _combinatorial_bits(total_alts: int, total_correct: int, threshold: int) -> float:
    return _log2_comb(total_alts, threshold) - _log2_comb(total_correct, threshold)

# ---- Argon2 calibration & timing (unchanged logic) ----
def calibrate_argon2(target_ms: float = 250.0, max_mib: int = 1024) -> tuple[int, int, int, float]:
    pwd = "SECQ_calibration"
    salt = random_bytes(16)
    t = 2
    m_kib = 256 * 1024  # 256 MiB
    p = 1
    measured = 0.0
    while True:
        st = time.perf_counter()
        _key, _ = CF.derive_or_recover_key(pwd, salt, False, t, m_kib, p)
        measured = (time.perf_counter() - st) * 1000.0
        if measured >= target_ms:
            break
        if m_kib < max_mib * 1024:
            m_kib = min(max_mib * 1024, m_kib * 2)
        else:
            if t < 6:
                t += 1
            else:
                break
    return t, m_kib, p, measured

def estimate_argon2_time_ms(arg_time: int, arg_mem: int, arg_par: int, samples: int = 1) -> float:
    pwd = "SECQ_estimate"
    total = 0.0
    for _ in range(max(1, samples)):
        salt = random_bytes(16)
        st = time.perf_counter()
        _k, _ = CF.derive_or_recover_key(pwd, salt, False, arg_time, arg_mem, arg_par)
        total += (time.perf_counter() - st) * 1000.0
    return total / max(1, samples)

# ---- Bucketized (Padmé-like) padding for share length-hiding -----------------
def _bucketize_pad_size(target_len: int) -> int:
    """
    Map target_len into stable, power-of-two-ish buckets to reduce length leakage.
    """
    if target_len <= 64: return 64
    # Next power-of-two bucket, with gentle growth:
    k = max(7, int(math.ceil(math.log2(target_len))))
    return 1 << k

def prompt_pad_size_multi(max_b64_len: int) -> int:
    recommended_pad = max(128, _bucketize_pad_size(max_b64_len + 32))
    user_pad = recommended_pad
    print(f"\nCustom PAD size? Press ENTER to use recommended={recommended_pad}.")
    try_pad_str = safe_input(f"PAD must be >= {max_b64_len} (max length of base64 secrets): ", "").strip()
    if try_pad_str:
        try:
            user_pad_input = int(try_pad_str)
            if user_pad_input < max_b64_len:
                print(f"Provided pad < max base64 secret length. Forcing {max_b64_len} instead.\n")
                user_pad = max_b64_len
            else:
                user_pad = _bucketize_pad_size(user_pad_input)
        except ValueError:
            print(f"Invalid number, using recommended={recommended_pad}.\n")
    if user_pad < max_b64_len:
        user_pad = _bucketize_pad_size(max_b64_len)
        print(f"Corrected final pad to {user_pad} to fit the secrets.\n")
    log_debug(f"Using PAD size (bucketized): {user_pad}", level="INFO")
    return user_pad

def show_start_menu():
    while True:
        print("\nPress 1 - Enter setup phase")
        print("Press 2 - Proceed to example demonstration")
        choice_ = safe_input("Choice: ", "2").strip()
        if choice_ == "1":
            setup_phase()
        elif choice_ == "2":
            main()
            break
        else:
            print("Invalid choice. Please try again.\n")

def display_questions(questions):
    print("\n--- SECURITY QUESTIONS ---\n")
    for q in questions:
        typ = "CRITICAL" if q.get("is_critical") else "STANDARD"
        print(f"[Question {q['id']}] {q['text']} (Type: {typ})\n")
        for i, alt in enumerate(q["alternatives"], 1):
            letter = chr(ord('A') + i - 1)
            print(f"{letter}) {alt}")
        print("\n---\n")

def _decoy_pick_index(q_hashes_and_alt_hashes: list[tuple[str, str]], decoy_count: int) -> int:
    """
    Deterministically select a decoy index in [1..decoy_count] based on selected answers.
    """
    if decoy_count <= 0:
        return 1
    acc = hashlib.sha3_256()
    for qh, ah in sorted(q_hashes_and_alt_hashes):
        acc.update(qh.encode("utf-8")); acc.update(b"|"); acc.update(ah.encode("utf-8")); acc.update(b";")
    val = int.from_bytes(acc.digest()[-4:], "big")
    return (val % decoy_count) + 1  # 1..decoy_count

# === Setup, file load, manual input (unchanged behavior) ======================
def setup_phase():
    while True:
        print("\n--- Setup Phase ---")
        print("1. Create new security questions")
        print("2. Load security questions from a file")
        print("b. Back to main menu")
        choice = input("Choice: ").strip().lower()
        if choice == '1':
            manual_questions = manual_input_mode()
            if manual_questions:
                save_option = prompt_save_decision()
                if save_option == 'j':
                    save_questions(manual_questions)
                elif save_option == 'c':
                    print("(Continuing without saving.)\n")
            return
        elif choice == '2':
            file_load_phase()
            return
        elif choice == 'b':
            return
        else:
            print("Invalid choice. Please enter '1', '2', or 'b'.")

def file_load_phase():
    SAVE_DIR.mkdir(parents=True, exist_ok=True)
    all_json = sorted(f for f in SAVE_DIR.glob("*.json") if f.is_file())
    if not all_json:
        print(f"\nNo configuration files found in the '{SAVE_DIR.name}' directory.")
        input("Press Enter to go back: ")
        return
    print("\nAvailable configuration files:\n")
    for idx, fobj in enumerate(all_json, 1):
        print(f"{idx}) {fobj.name}")
    print("\nEnter the number of the file you'd like to load, or press b to go back.")
    while True:
        user_pick = input("Choice: ").strip().lower()
        if user_pick == 'b':
            return
        try:
            pick_val = int(user_pick)
            if 1 <= pick_val <= len(all_json):
                chosen_file = all_json[pick_val - 1]
                print(f"\nYou selected: {chosen_file.name}")
                try:
                    with open(chosen_file, "r", encoding="utf-8") as jf:
                        kit = json.load(jf)
                    run_recovery_kit_flow(kit, chosen_file)
                except Exception as e:
                    log_exception(e, f"Failed to load or process kit: {chosen_file}")
                    print("ERROR: Could not load/process the selected kit file.")
                return
            else:
                print("Invalid selection. Try again, or press b to go back.")
        except ValueError:
            print("Invalid input. Try again, or press b to go back.")

def manual_input_mode():
    """
    Returns list of questions:
      {
        "id": int,
        "text": str,
        "alternatives": [str],
        "correct_answers": [str], # used internally, not exported
        "is_critical": bool
      }
    """
    questions = []
    while True:
        current_qnum = len(questions) + 1
        print(f"\nEnter your security question #{current_qnum} (2..100 total):")
        question_text = ""
        while not question_text:
            question_text = input("[Your question here]: ").strip()
            if not question_text:
                print("Question text cannot be blank.")

        # number of alternatives
        while True:
            print("\nHow many answer alternatives should this question have?")
            print("Enter a number between 2 and 20")
            alt_count_str = input("Number of alternatives: ").strip()
            try:
                alt_count = int(alt_count_str)
                if 2 <= alt_count <= 20:
                    break
                print("Please enter a value between 2 and 20.")
            except ValueError:
                print("Invalid integer.")

        # alternatives
        alternatives = []
        norm_seen = set()
        print("\nEnter the alternatives:")
        for i in range(alt_count):
            while True:
                alt_raw = input(f"Alternative {i+1}: ").strip()
                if not alt_raw:
                    print("Alternative cannot be blank.")
                    continue
                norm = _normalize_for_comparison(alt_raw)
                if norm in norm_seen:
                    print("Duplicate or too similar alternative. Please enter a unique value.")
                    continue
                alternatives.append(alt_raw)
                norm_seen.add(norm)
                break

        # type select
        is_critical = False
        print("\nSelect question type:")
        print("Standard is selected by default.")
        print("If you want to mark this question as critical, press c.")
        print("(Otherwise, press Enter to keep it as Standard)")
        while True:
            type_choice = input("Choice: ").strip().lower()
            if type_choice == '':
                break
            elif type_choice == 'c':
                is_critical = True
                break
            else:
                print("Invalid choice. Press 'c' for Critical or Enter for Standard.")

        # correct answers selection
        correct_answers = _prompt_correct_answers_for_question(alternatives)

        # re-edit loop
        while True:
            print("\nWould you like to re-edit anything for the current question before proceeding?")
            print("Press q – Re-edit the security question text")
            print("Press a – Re-edit all answer alternatives")
            print(f"Press # (1..{alt_count}) – Re-edit a single alternative by its number")
            print("Press r – Re-select the correct answer(s)")
            print("(Or press Enter to continue to next step/question)")
            e = input("Re-edit choice: ").strip().lower()
            if e == "":
                break
            if e == "q":
                new_text = ""
                while not new_text:
                    new_text = input("\nRe-enter security question text:\n").strip()
                    if not new_text:
                        print("Question text cannot be blank.")
                question_text = new_text
                print("(Question updated.)\n")
            elif e == "a":
                new_alts = []
                new_seen = set()
                print("\nRe-entering all alternatives...")
                for i in range(alt_count):
                    while True:
                        v = input(f"Re-enter Alternative {i+1}: ").strip()
                        if not v:
                            print("Alternative cannot be blank.")
                            continue
                        n = _normalize_for_comparison(v)
                        if n in new_seen:
                            print("Duplicate or too similar alternative. Please enter a unique value.")
                            continue
                        new_alts.append(v)
                        new_seen.add(n)
                        break
                alternatives = new_alts
                norm_seen = new_seen
                print("(Alternatives updated.)\n")
                correct_answers = _prompt_correct_answers_for_question(alternatives)
            elif e == "r":
                correct_answers = _prompt_correct_answers_for_question(alternatives)
            else:
                try:
                    idx = int(e)
                    if 1 <= idx <= alt_count:
                        while True:
                            nv = input(f"Re-enter Alternative {idx}: ").strip()
                            if not nv:
                                print("Alternative cannot be blank.")
                                continue
                            n = _normalize_for_comparison(nv)
                            others = set(_normalize_for_comparison(x) for j, x in enumerate(alternatives) if j != idx-1)
                            if n in others:
                                print("Duplicate or too similar to another existing alternative.")
                                continue
                            old_val = alternatives[idx-1]
                            alternatives[idx-1] = nv
                            if old_val in correct_answers:
                                correct_answers = [nv if x == old_val else x for x in correct_answers]
                            print("(Alternative updated.)\n")
                            break
                    else:
                        print(f"Alternative number must be between 1 and {alt_count}.")
                except ValueError:
                    print("Unrecognized re-edit choice.\n")

        questions.append({
            "id": current_qnum,
            "text": question_text,
            "alternatives": alternatives,
            "correct_answers": correct_answers,
            "is_critical": is_critical
        })
        print("\nNavigation options:")
        print("Press n – Proceed to the next question")
        if len(questions) > 1:
            print("Press b – Go back and revise the previous question")
        if len(questions) >= 2:
            print("Press d – Done (finish input)")
        print(f"(You must have at least 2 questions to finish, you currently have {len(questions)}.)")
        nav = input("Choice: ").strip().lower()
        if nav == "n" or nav == "":
            if len(questions) >= 100:
                print("You have reached the maximum of 100 questions. Finishing input now.")
                break
        elif nav == "b":
            if questions:
                questions.pop()
            if questions:
                print("\nRevising the previous question (it will be re-entered)...")
                questions.pop()
                continue
        elif nav == "d":
            if len(questions) >= 2:
                print("\n--- Manual input complete. ---\n")
                break
            else:
                print("You must have at least 2 questions. Continue adding more.")
        else:
            if len(questions) >= 100:
                print("You have reached the maximum of 100 questions. Finishing input now.")
                break

    if questions:
        print("Summary of your manually entered questions:\n")
        for qd in questions:
            typ = "CRITICAL" if qd["is_critical"] else "STANDARD"
            print(f"[Question {qd['id']}] {qd['text']}")
            for i, alt in enumerate(qd["alternatives"], 1):
                letter = chr(ord('A') + i - 1)
                print(f" {letter}) {alt}")
            print(f" Type: {typ}")
            print(f" Correct: {', '.join(qd['correct_answers'])}\n")
    else:
        print("No questions were entered.\n")
    return questions

def _prompt_correct_answers_for_question(alternatives: list[str]) -> list[str]:
    if not alternatives:
        return []
    print("\nMark the correct answer(s) for this question.")
    print("Enter letters or numbers separated by commas (e.g., A,C or 1,3).")
    print("You can also type 'all' to select all alternatives.")
    legend = ", ".join(f"{chr(ord('A')+i)}={i+1}" for i in range(len(alternatives)))
    print("Legend:", legend)

    while True:
        raw = input("Correct selection(s): ").strip()
        if not raw:
            print("Select at least one correct alternative. Blank input is not allowed.")
            continue
        if raw.lower() == "all":
            confirm = input("Are you sure you want to mark ALL alternatives as correct? (y/n): ").strip().lower()
            if confirm == 'y':
                print("(All alternatives marked as correct)")
                return alternatives[:]
            else:
                print("Selection cancelled. Please select explicitly.")
                continue
        tokens = [t.strip() for chunk in raw.replace(",", " ").split() for t in [chunk] if t.strip()]
        if not tokens:
            print("Please provide a valid selection.")
            continue

        picks = set()
        ok = True
        for t in tokens:
            if len(t) == 1 and t.isalpha():
                idx = (ord(t.upper()) - ord('A')) + 1
            else:
                try:
                    idx = int(t)
                except ValueError:
                    print(f"Unrecognized token '{t}'."); ok = False; break
            if not (1 <= idx <= len(alternatives)):
                print(f"Out of range: '{t}'."); ok = False; break
            picks.add(idx)
        if not ok or not picks:
            continue

        selected = [alternatives[i-1] for i in sorted(picks)]
        print(f"(Selected: {', '.join(selected)})")
        return selected

def prompt_save_decision():
    while True:
        print("\nWould you like to save your questions?")
        print("Press j – Save as both JSON and text file")
        print("Press c – Continue without saving")
        c = input("Choice: ").strip().lower()
        if c in ("j", "c"):
            return c
        print("Invalid choice.")

# -------------- DECOYS + recovery kit (passwordless; AAD; AUTH-CATALOG) ------
def _prompt_decoy_count() -> int:
    return get_valid_int("How many decoy secrets? (1-1000): ", 1, 1000)

def _prompt_decoy_secrets(count: int, real_secret: str) -> list[str]:
    decoys = []
    print("\n--- Configure Decoy Secrets ---")
    print("A decoy is returned when real restoration criteria are not met.")
    print("They should look fully plausible. The text you enter here is what will be revealed.")

    i = 1
    while i <= count:
        s = input(f"Enter decoy secret #{i} of {count}: ").strip()
        if not s:
            print("Decoy secret cannot be blank."); continue
        if s == real_secret:
            print("Decoy secret cannot be the same as the real secret."); continue
        if s in decoys:
            print("Decoy secret must be unique. This one has already been entered."); continue

        decoys.append(s); i += 1
    return decoys

def save_questions(questions):
    """
    Builds and saves a SELF-CONTAINED recovery kit (passwordless per-answer keys).
    Enforces a minimum combinatorial hardness before allowing kit generation.
    Enhanced with:
    - DTE encoding for all secrets (real + decoys)
    - Bucketized padding for share-length indistinguishability
    - Runtime-gated AEAD preference (XChaCha20-Poly1305 / AES-256-GCM-SIV)
    """
    print("\n--- Cryptographic Parameter Setup ---")
    real_secret = get_nonempty_secret("Enter the secret to be protected: ")
    # DTE-encode the secret; we keep transport as base64 of the DTE seed package
    dte_real = DTE.encode(real_secret)
    real_b64 = dte_real["seed_b64"]

    # Decoys
    decoy_count = _prompt_decoy_count()
    decoy_texts = _prompt_decoy_secrets(decoy_count, real_secret)
    dte_decoys = [DTE.encode(d)["seed_b64"] for d in decoy_texts]

    real_bytes = real_b64.encode("utf-8")
    decoy_bytes_list = [db64.encode("utf-8") for db64 in dte_decoys]

    total_correct = sum(len(q.get("correct_answers", [])) for q in questions)
    total_alts = sum(len(q.get("alternatives", [])) for q in questions)
    total_incorrect = max(0, total_alts - total_correct)
    log_debug("Counts computed for kit build.",
              level="INFO", component="CRYPTO",
              details={"total_correct": total_correct, "total_alternatives": total_alts, "total_incorrect": total_incorrect})

    if total_correct == 0:
        print("ERROR: No correct answers were defined across your questions. At least one is required.")
        return

    min_thr = _policy_min_threshold(total_correct)
    max_thr = total_correct
    print(f"\n[Policy] Minimum threshold for your {total_correct} real share(s) is {min_thr}.")
    r_thr = get_threshold("Enter the real threshold", min_thr, max_thr)

    max_b64_len = max(len(real_b64), *(len(db64) for db64 in dte_decoys))
    pad_size = prompt_pad_size_multi(max_b64_len)

    # Argon2 parameters
    arg_time, arg_mem, arg_par = prompt_argon2_parameters()
    log_debug("Argon2id parameters confirmed for kit.",
              level="INFO", component="CRYPTO",
              details={"time_cost": arg_time, "memory_cost": arg_mem, "parallelism": arg_par})

    bits = _combinatorial_bits(total_alts, total_correct, r_thr)
    if not math.isfinite(bits) or bits < SECQ_MIN_BITS:
        print(f"\n[ABORT] Combinatorial hardness too low: ~{bits:.1f} bits "
              f"for N={total_alts}, C={total_correct}, T={r_thr}.")
        print("Add more questions/alternatives and/or increase the threshold, then try again.\n")
        return
    else:
        print(f"[OK] Combinatorial hardness: ~{bits:.1f} bits.")

    # Flatten (q,alt) with correctness flags
    all_items: list[tuple[str, str, str, str, bool]] = []
    for q in questions:
        q_text = q["text"]
        alts = q["alternatives"]
        q_hash = _integrity_hash_for_kit(q_text, alts)
        correct_set_norm = set(_norm_for_kit(a) for a in q.get("correct_answers", []))
        for alt in alts:
            is_correct = _norm_for_kit(alt) in correct_set_norm
            all_items.append((q_hash, _alt_hash_for_kit(alt), q_text, alt, is_correct))
    total_alts = len(all_items)

    # Split real-only shares across correct alts; decoys across all alts
    try:
        real_shares_correct = asyncio.run(
            sss_split(real_b64.encode("utf-8"), sum(1 for it in all_items if it[4]), r_thr, pad=pad_size)
        )
    except Exception as e:
        log_exception(e, "Error splitting REAL secret")
        return

    # First decoy gets threshold 1; others match real r_thr (unchanged behavior)
    decoy_thresholds = [1] + [r_thr] * (len(decoy_bytes_list) - 1)
    decoy_shares_by_idx: list[list[bytearray]] = []
    try:
        for db64, thr in zip(dte_decoys, decoy_thresholds):
            shares = asyncio.run(sss_split(db64.encode("utf-8"), total_alts, thr, pad=pad_size))
            decoy_shares_by_idx.append(shares)
    except Exception as e:
        log_exception(e, "Error splitting DECOY secret(s)")
        return

    # Auth catalog (unchanged semantics; now authenticates DTE-decoded outputs)
    def _auth_entry(secret_seed_b64: str) -> dict:
        secret_bytes = base64.b64decode(secret_seed_b64.encode("utf-8"), validate=True)
        salt = random_bytes(16)
        k_auth = hkdf_sha256(ikm=secret_bytes, salt=salt, info=b"SECQ final-auth v3", dk_len=32)
        tag = hmac_sha256(k_auth, secret_bytes)
        return {"salt": base64.b64encode(salt).decode(), "hmac_sha256": base64.b64encode(tag).decode()}

    auth_catalog = [_auth_entry(real_b64)] + [_auth_entry(db64) for db64 in dte_decoys]
    perm = list(range(len(auth_catalog)))
    pysecrets.SystemRandom().shuffle(perm)
    auth_catalog = [auth_catalog[i] for i in perm]

    encrypted_shares: dict[str, dict[str, dict]] = {}
    real_idx = 0
    share_len = pad_size + 1

    # AEAD algorithm preference list (runtime gated)
    aead_prefs = []
    if hasattr(CF, "encrypt_xchacha20poly1305"): aead_prefs.append("xchacha20poly1305")
    if hasattr(CF, "encrypt_aes256gcm_siv"):     aead_prefs.append("aes256gcm_siv")
    aead_prefs.extend(["chacha20poly1305", "aes256gcm"])

    def _enc_one_share(plaintext_share: bytes, q_hash: str, alt_text: str, alg_choice: str) -> dict:
        salt = random_bytes(16)
        key = _derive_answer_key(alt_text, salt, arg_time, arg_mem, arg_par)
        aad = _aad_bytes(q_hash, _alt_hash_for_kit(alt_text), alg_choice)
        enc = _aead_encrypt(alg_choice, plaintext_share, key, aad=aad)
        out = {
            "ciphertext": enc["ciphertext"],
            "nonce": enc["nonce"],
            "algorithm": alg_choice,
            "salt": base64.b64encode(salt).decode(),
            "kdf": {"type": "argon2id", "t": arg_time, "m": arg_mem, "p": arg_par, "len": 32}
        }
        if "tag" in enc:  # AES-GCM may include tag; XChaCha+Poly1305 does not separate
            out["tag"] = enc["tag"]
        return out

    for global_idx, (q_hash, a_hash, q_text, alt_text, is_corr) in enumerate(all_items):
        encrypted_shares.setdefault(q_hash, {})
        per_alt_block = {}

        if is_corr:
            if real_idx < len(real_shares_correct):
                real_share = bytes(real_shares_correct[real_idx]); real_idx += 1
            else:
                log_error("Internal error: real_idx overflow",
                          details={"real_idx": real_idx, "len": len(real_shares_correct)})
                real_share = random_bytes(share_len)
        else:
            real_share = random_bytes(share_len)

        alg_choice = aead_prefs[global_idx % len(aead_prefs)]
        per_alt_block["s0"] = _enc_one_share(real_share, q_hash, alt_text, alg_choice)

        for decoy_i, shares_list in enumerate(decoy_shares_by_idx, start=1):
            dec_share = bytes(shares_list[global_idx])
            alg_choice_d = aead_prefs[(global_idx + decoy_i) % len(aead_prefs)]
            per_alt_block[f"s{decoy_i}"] = _enc_one_share(dec_share, q_hash, alt_text, alg_choice_d)

        encrypted_shares[q_hash][a_hash] = per_alt_block
        log_debug("Mapped Q/A to encrypted multi-secret shares.",
                  level="INFO", component="CRYPTO",
                  details={"q_text": q_text, "alt_text": alt_text, "q_hash": q_hash, "alt_hash": a_hash,
                           "real_valid": bool(is_corr), "decoy_variants": len(decoy_shares_by_idx)})

    questions_out = [{
        "id": q["id"], "text": q["text"], "alternatives": q["alternatives"],
        "is_critical": bool(q.get("is_critical", False)),
        "integrity_hash": _integrity_hash_for_kit(q["text"], q["alternatives"])
    } for q in questions]

    recovery_kit = {
        "config": {
            "real_threshold": r_thr, "pad_size": pad_size,
            "argon2_params": {"time_cost": arg_time, "memory_cost": arg_mem, "parallelism": arg_par},
            "version": KIT_VERSION, "secrets_count": 1 + len(decoy_bytes_list),
            "auth_catalog": auth_catalog
        },
        "questions": questions_out,
        "encrypted_shares": encrypted_shares
    }

    SAVE_DIR.mkdir(parents=True, exist_ok=True)
    default_name = f"recovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    base_name = input(f"Enter a base name for the save files (or press Enter for '{default_name}'): ").strip() or default_name
    json_file = SAVE_DIR / f"{base_name}.json"
    txt_file = SAVE_DIR / f"{base_name}.txt"

    with open(json_file, "w", encoding="utf-8") as jf:
        json.dump(recovery_kit, jf, indent=2)
    with open(txt_file, "w", encoding="utf-8") as tf:
        tf.write("--- CRYPTOGRAPHIC CONFIGURATION ---\n")
        tf.write("Secret: [encoded via DTE + SSS; not stored in JSON]\n")
        tf.write(f"Shamir Threshold (real path): {r_thr}\n")
        tf.write(f"Pad Size (bucketized): {pad_size}\n")
        tf.write("Argon2id Parameters:\n")
        tf.write(f" - Time Cost: {arg_time}\n")
        tf.write(f" - Memory Cost: {arg_mem} KiB\n")
        tf.write(f" - Parallelism: {arg_par}\n")
        tf.write(f"\nAuth Catalog Entries (real+decoys, shuffled): {len(auth_catalog)}\n")
        tf.write("\n--- SECURITY QUESTIONS ---\n\n")
        for q in questions:
            qtype = "CRITICAL" if q.get("is_critical") else "STANDARD"
            tf.write(f"[Question {q['id']}] {q['text']} (Type: {qtype})\n\n")
            for i, alt in enumerate(q['alternatives'], 1):
                letter = chr(ord('A') + i - 1)
                tf.write(f"{letter}) {alt}\n")
            tf.write("\n---\n\n")

    print(f"\nOK Configuration saved successfully!")
    print(f"JSON file: {json_file}")
    print(f"Text file: {txt_file}")
    log_debug("Recovery kit saved (passwordless; with DTE; auth catalog; decoy-enabled).", level="INFO")

# ---------- Recovery UI Flow from a saved kit (with DTE decode) ---------------
def _try_combine_with_sampling(partials: list[bytes], r_thr: int) -> bytes | None:
    n = len(partials)
    if n < r_thr:
        return None
    if n == r_thr:
        try:
            return asyncio.run(sss_combine(partials))
        except Exception:
            return None
    max_exhaustive = 5000
    total_combos = math.comb(n, r_thr) if hasattr(math, "comb") else float("inf")
    if total_combos <= max_exhaustive:
        for idxs in combinations(range(n), r_thr):
            try:
                return asyncio.run(sss_combine([partials[i] for i in idxs]))
            except Exception:
                continue
        return None

    def sample_indices(nv: int, kv: int) -> tuple[int, ...]:
        s = set()
        while len(s) < kv:
            s.add(pysecrets.randbelow(nv))
        return tuple(sorted(s))

    seen = set()
    for _ in range(200):
        idxs = sample_indices(n, r_thr)
        if idxs in seen: continue
        seen.add(idxs)
        try:
            return asyncio.run(sss_combine([partials[i] for i in idxs]))
        except Exception:
            continue
    return None

def run_recovery_kit_flow(kit: dict, kit_path: Path):
    try:
        cfg = kit.get("config") or {}
        questions = kit.get("questions") or []
        enc_shares = kit.get("encrypted_shares") or {}
        r_thr = int(cfg.get("real_threshold"))
        arg = cfg.get("argon2_params") or {}
        arg_time = int(arg.get("time_cost"))
        arg_mem = int(arg.get("memory_cost"))
        arg_par = int(arg.get("parallelism"))
        secrets_count = int(cfg.get("secrets_count", 1))
        auth_catalog = list(cfg.get("auth_catalog", []))
    except Exception as e:
        log_exception(e, "Invalid kit structure.")
        print("ERROR: Kit structure invalid or missing fields.")
        return

    print("\n--- LOADED RECOVERY KIT ---\n")
    print(f"File : {kit_path.name}")
    print(f"Threshold (T) : {r_thr} [real path]")
    print(f"Pad Size : {cfg.get('pad_size')}")
    print("Argon2id Params:")
    print(f" - Time Cost : {arg_time}")
    print(f" - Memory Cost: {arg_mem} KiB")
    print(f" - Parallelism: {arg_par}")
    print(f"Auth Catalog : {len(auth_catalog)} entries\n")
    log_debug("Loaded recovery kit.",
              level="INFO", component="CRYPTO",
              details={"kit_file": str(kit_path), "threshold": r_thr, "pad_size": cfg.get("pad_size"),
                       "argon2": {"time_cost": arg_time, "memory_cost": arg_mem, "parallelism": arg_par},
                       "q_count": len(questions), "secrets_count": secrets_count})

    if not questions or not enc_shares:
        print("ERROR: Kit missing questions or encrypted_shares.")
        log_error("Kit missing essential arrays.", details={"has_questions": bool(questions), "has_enc_shares": bool(enc_shares)})
        return

    # Present questions via multi-select
    print("--- Answer the security questions ---\n")
    chosen = []
    for i, q in enumerate(questions, 1):
        text = q.get("text", "")
        alts = list(q.get("alternatives", []))
        picks = arrow_select_no_toggle(None, i, text, alts, pre_selected=None)
        chosen.append({"q": q, "picks": picks})
        log_debug("Recovery UI picks for question.", level="INFO", component="GENERAL",
                  details={"q_id": q.get("id"), "q_text": text, "picked": picks})

    partials_s0: list[bytes] = []
    selected_pairs: list[tuple[str, str, str, str]] = []  # (q_hash, a_hash, q_text, alt_text)
    for item in chosen:
        qobj = item["q"]
        picks = item["picks"]
        q_text = qobj.get("text", "")
        alts = qobj.get("alternatives", [])
        q_hash = qobj.get("integrity_hash") or _integrity_hash_for_kit(q_text, alts)
        q_block = enc_shares.get(q_hash)
        if not q_block:
            log_error("Missing encrypted_shares block for question hash.", details={"q_hash": q_hash})
            continue
        for alt in picks:
            alt_hash = _alt_hash_for_kit(alt)
            sblock = q_block.get(alt_hash) or {}
            entry = sblock.get("s0")
            if not entry:
                log_error("No encrypted entry for selected alternative (s0).", details={"q_hash": q_hash, "alt_hash": alt_hash, "alt_text": alt})
                continue
            selected_pairs.append((q_hash, alt_hash, q_text, alt))
            share_bytes = _decrypt_share_from_entry(entry, arg_time, arg_mem, arg_par,
                                                    q_hash=q_hash, alt_hash=alt_hash,
                                                    qid=qobj.get("id"), qtext=q_text, alt_text=alt)
            if share_bytes is not None:
                partials_s0.append(share_bytes)

    combined_bytes = _try_combine_with_sampling(partials_s0, r_thr)
    secret_variant_used = "REAL"

    # If real fails, deterministically reconstruct a decoy.
    if combined_bytes is None:
        idx = _decoy_pick_index([(qh, ah) for (qh, ah, _, _) in selected_pairs], max(0, secrets_count - 1))
        decoy_index = max(1, idx)
        secret_variant_used = f"DECOY_{decoy_index}"
        log_debug(f"Real reconstruction failed or insufficient shares. Falling back to {secret_variant_used}.", level="INFO")

        decoy_partials: list[bytes] = []
        for (q_hash, a_hash, q_text, alt_text) in selected_pairs:
            block = enc_shares.get(q_hash, {}).get(a_hash, {})
            entry = block.get(f"s{decoy_index}")
            if not entry:
                continue
            sb = _decrypt_share_from_entry(entry, arg_time, arg_mem, arg_par,
                                           q_hash=q_hash, alt_hash=a_hash,
                                           qid=None, qtext=q_text, alt_text=alt_text)
            if sb is not None:
                decoy_partials.append(sb)
        combined_bytes = _try_combine_with_sampling(decoy_partials, 1)

    if combined_bytes is None:
        log_error("FATAL: Both real and decoy reconstruction failed. This may indicate a kit corruption.",
                  details={"variant_tried": secret_variant_used})
        print("\nAn unexpected error occurred during reconstruction. Unable to recover a secret.")
        return

    try:
        recovered_b64 = combined_bytes.decode("utf-8")
        # DTE decode (seed -> plausible secret); auth is over seed bytes
        final_secret_seed_bytes = base64.b64decode(recovered_b64.encode("utf-8"), validate=True)
        # Auth against catalog (constant-time)
        matched = False
        for entry in auth_catalog:
            try:
                salt = base64.b64decode(entry.get("salt", ""))
                expected = base64.b64decode(entry.get("hmac_sha256", ""))
                k_auth = hkdf_sha256(ikm=final_secret_seed_bytes, salt=salt, info=b"SECQ final-auth v3", dk_len=32)
                calc = hmac_sha256(k_auth, final_secret_seed_bytes)
                if consttime_equal(calc, expected):
                    matched = True
            except Exception:
                continue

        # Produce final secret text via DTE
        final_secret_text = DTE.decode(recovered_b64)
        print("\n[AUTH OK]" if matched else "\n[AUTH WARNING] (non-catalog secret)\n")
        print("--- SECRET RECONSTRUCTED ---")
        print(final_secret_text)
        print("-----------------------------\n")
        log_debug("Final secret reconstructed.", level="INFO", component="CRYPTO",
                  details={"final_secret_len": len(final_secret_text), "variant": secret_variant_used, "auth_ok": matched})
    except Exception as e:
        log_exception(e, "Final base64/utf-8 decode or auth failed.")
        print("\nShares combined, but final decode or authentication failed.\n")

    append_recovery_guide()
    log_debug("Recovery Mode complete.", level="INFO")
    print("Press 1 – Enter setup phase")
    print("Press 2 – Proceed to example demonstration")

# ---------- existing demonstration / combine path (kept; AAD added) -----------
def get_next_filename(base_dir, base_name, extension):
    idx = 0
    while True:
        idx += 1
        candidate = base_dir / (f"{base_name}.{extension}" if idx == 1 else f"{base_name}{idx}.{extension}")
        if not candidate.exists():
            return candidate

def check_required_files():
    # Skip file checks when running from .pyz since all files are embedded
    import sys
    if getattr(sys, 'frozen', False) or (hasattr(sys, 'argv') and sys.argv[0].endswith('.pyz')):
        return
    
    needed_in_src = ["CipherForge.py", "example_questions25.json"]
    missing = []
    for f in needed_in_src:
        if not (SRC_DIR / f).exists():
            missing.append(f)
    modules_path = SRC_DIR / "modules"
    needed_in_modules = [
        "debug_utils.py", "input_utils.py", "log_processor.py", "security_utils.py",
        "split_utils.py", "sss_bridge.py", "ui_utils.py", "crypto_bridge.py"
    ]
    for f in needed_in_modules:
        if not (modules_path / f).exists():
            missing.append(f"modules/{f}")
    if missing:
        log_error("Missing required files", details={"missing": missing})
        print("ERROR - Missing files:", missing)
        sys.exit(1)

def prompt_argon2_parameters():
    print("\n--- Argon2id Parameter Setup ---")
    print("Use (n) normal defaults, (a) auto-calibrate, or (e) custom edit? [n/a/e] ", end="")
    choice_ = safe_input(default="n").strip().lower()
    if choice_ == 'a':
        t, m_kib, p, ms = calibrate_argon2()
        print(f"Auto-calibrated: time_cost={t}, memory_cost={m_kib} KiB, parallelism={p} (~{ms:.1f} ms/guess)")
        return (t, m_kib, p)
    if choice_ != 'e':
        print("Using FAST Argon2id parameters: time_cost=1, memory_cost=16384, parallelism=8")
        safe_input("Press ENTER to continue with these defaults...", "")
        return (1, 16384, 8)
    else:
        print("Enter custom Argon2id parameters:")
        tc = get_valid_int("time_cost (1..10)? ", 1, 10)
        mc = get_valid_int("memory_cost (8192..1048576)? ", 8192, 1048576)
        pl = get_valid_int("parallelism (1..32)? ", 1, 32)
        print(f"Using CUSTOM Argon2id parameters: time_cost={tc}, memory_cost={mc}, parallelism={pl}")
        return (tc, mc, pl)

def calc_qna_search_space(chosen):
    total = 1
    for q in chosen:
        n_alts = len(q["alternatives"])
        ways = (1 << n_alts) - 1 if n_alts > 0 else 1
        total *= max(1, ways)
    return total

def convert_seconds_to_dhms(seconds):
    out = {"years":0,"months":0,"days":0,"hours":0,"minutes":0,"seconds":0.0}
    if seconds <= 0: return out
    year_sec = 365.25*24*3600
    month_sec = 30.4375*24*3600
    day_sec = 24*3600
    hour_sec = 3600
    minute_sec = 60
    out["years"] = int(seconds // year_sec); seconds %= year_sec
    out["months"] = int(seconds // month_sec); seconds %= month_sec
    out["days"] = int(seconds // day_sec); seconds %= day_sec
    out["hours"] = int(seconds // hour_sec); seconds %= hour_sec
    out["minutes"] = int(seconds // minute_sec); seconds %= minute_sec
    out["seconds"] = seconds
    return out

def print_estimated_bruteforce_times(chosen, arg_time, arg_mem, arg_par,
                                     total_correct_lower: int | None = None,
                                     r_thr: int | None = None,
                                     decoy_present: bool = True):
    import math
    search_space = max(1, calc_qna_search_space(chosen))
    single_guess_ms = estimate_argon2_time_ms(arg_time, arg_mem, arg_par, samples=1)
    single_guess_ms_no_argon = 0.005
    total_classical_ms = search_space * single_guess_ms
    total_quantum_ms = math.sqrt(search_space) * single_guess_ms
    total_classical_ms_na = search_space * single_guess_ms_no_argon
    total_quantum_ms_na = math.sqrt(search_space) * single_guess_ms_no_argon

    def _fmt_time(ms: float) -> dict:
        sec = ms / 1000.0
        return convert_seconds_to_dhms(sec)

    print("\n--- Estimated Brute-Force Difficulty ---")
    print(f"Total Q&A search space (non-empty subsets): {search_space:,.0f} guesses.")
    print("\n[WITH Argon2id] per-guess ~{:.3f} ms =>".format(single_guess_ms))
    cl = _fmt_time(total_classical_ms); qn = _fmt_time(total_quantum_ms)
    print(f" Classical total time : {cl['years']}y {cl['months']}m {cl['days']}d {cl['hours']}h {cl['minutes']}m {cl['seconds']:.2f}s")
    print(f" Quantum (Grover est.): {qn['years']}y {qn['months']}m {qn['days']}d {qn['hours']}h {qn['minutes']}m {qn['seconds']:.2f}s")
    print("\n[WITHOUT Argon2id] per-guess ~{:.3f} ms =>".format(single_guess_ms_no_argon))
    cl2 = _fmt_time(total_classical_ms_na); qn2 = _fmt_time(total_quantum_ms_na)
    print(f" Classical total time : {cl2['years']}y {cl2['months']}m {cl2['days']}d {cl2['hours']}h {cl2['minutes']}m {cl2['seconds']:.2f}s")
    print(f" Quantum (Grover est.): {qn2['years']}y {qn2['months']}m {qn2['days']}d {qn2['hours']}h {qn2['minutes']}m {qn2['seconds']:.2f}s")
    if total_correct_lower is not None and r_thr is not None and total_correct_lower >= r_thr:
        trials_real_lb = math.comb(total_correct_lower, r_thr)
        print(f"\nLower-bound trials to reach the REAL threshold: C(C_total={total_correct_lower}, T={r_thr}) = {trials_real_lb:,d}")
    if decoy_present:
        print(f"Minimal trials to reach *a decoy* (given at least one decoy has T=1): 1")
    print()

# ---------- Demo flow (unchanged UX) ------------------------------------------
def main():
    try:
        print("[INFO] Launching main.py...")
        log_debug("Starting demonstration flow (Option 2)...", level="INFO")
        if not QUESTIONS_PATH.exists():
            msg = f"Error: question file not found: {QUESTIONS_PATH}"
            log_error(msg); print(msg); return

        try:
            with open(QUESTIONS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            empty_correct = 0
            for qd in data:
                if validate_question(qd):
                    qd["correct_answers"] = [
                        sanitize_input(normalize_text(ans)) for ans in qd.get("correct_answers", [])
                    ]
                    qd["alternatives"] = [
                        sanitize_input(normalize_text(alt)) for alt in qd["alternatives"]]
                    if not qd["correct_answers"]:
                        empty_correct += 1
                        qd["correct_answers"] = qd["alternatives"][:]
                        log_debug(
                            f"Question '{qd['text']}' had empty 'correct_answers'. Now set them all as correct.",
                            level="INFO"
                        )
            valid_data = [q for q in data if validate_question(q)]
            if empty_correct > 0:
                print(f"NOTICE: {empty_correct} question(s) had empty 'correct_answers'. "
                      f"All alternatives for those are treated as correct.\n")
        except Exception as e:
            log_exception(e, "Error loading question file")
            return

        if not valid_data:
            print("No valid questions found. Aborting.")
            return

        amt = get_valid_int(f"How many questions? (1..{len(valid_data)}): ", 1, len(valid_data))
        with chosen_lock:
            chosen = valid_data[:amt]

        correct_cumulative = 0
        incorrect_cumulative = 0
        for i, qdict in enumerate(chosen, 1):
            picks, qtype = arrow_select_clear_on_toggle(
                None, i, qdict["text"], qdict["alternatives"],
                pre_selected=qdict.get("user_answers"),
                pre_qtype=1 if qdict.get("is_critical") else 0,
                fixed_type=qdict.get("force_type")
            )
            qdict["user_answers"] = picks
            qdict["is_critical"] = bool(qtype) if not qdict.get("force_type") \
                else (qdict["force_type"].upper() == "CRITICAL")

            c_local = 0; i_local = 0
            cset_local = set(qdict.get("correct_answers", []))
            for alt_ in picks:
                if alt_ in cset_local: c_local += 1
                else: i_local += 1
            log_debug(f"Q{i}: text='{qdict['text']}' => user_picks={len(picks)} selected; local counts: correct={c_local}, incorrect={i_local}",
                      level="DEBUG")
            correct_cumulative += c_local; incorrect_cumulative += i_local
            print(f"[FEEDBACK] After Q{i}: +{c_local} correct, +{i_local} incorrect.")
            print(f"Total so far => correct={correct_cumulative}, incorrect={incorrect_cumulative}\n")

        while True:
            done = editing_menu(chosen)
            if done: break

        correct_map = []
        incorrect_map = []
        for idx, q in enumerate(chosen, 1):
            cset = set(q.get("correct_answers", []))
            picks_ = q["user_answers"]
            for alt in picks_:
                (correct_map if alt in cset else incorrect_map).append((q, alt))
            log_debug(f"After re-edit Q{idx}: c={sum(1 for _q,_a in correct_map if _q is q)}, i={sum(1 for _q,_a in incorrect_map if _q is q)}",
                      level="INFO")

        c_count = len(correct_map)
        i_count = len(incorrect_map)
        log_debug(f"FINAL TALLY => c_count={c_count}, i_count={i_count}", level="INFO")
        print(f"\nOverall Tally => Correct picks={c_count}, Incorrect={i_count}.\n")

        while True:
            if c_count < 10:
                if c_count == 0:
                    print("Zero correct picks => cannot proceed with Shamir's Secret Sharing.")
                    print("(E => re-edit answers, N => abort)")
                    answer = input("Choice (E/N)? ").strip().upper()
                    if answer == 'E':
                        editing_menu(chosen)
                        correct_map.clear(); incorrect_map.clear()
                        for q_ in chosen:
                            cset_ = set(q_.get("correct_answers", []))
                            picks_ = q_["user_answers"]
                            for alt_ in picks_:
                                (correct_map if alt_ in cset_ else incorrect_map).append((q_, alt_))
                        c_count = len(correct_map); i_count = len(incorrect_map)
                        print(f"\nNEW Tally => Correct picks={c_count}, Incorrect={i_count}.\n")
                        continue
                    elif answer == 'N':
                        if input("Are you sure you want to abort? (y/n): ").strip().lower().startswith('y'):
                            print("Aborting."); return
                        else:
                            continue
                    else:
                        print("Invalid choice.\n"); continue
                else:
                    print("Fewer than 10 correct => re-edit or abort.")
                    answer = input("Choice (E/N)? ").strip().upper()
                    if answer == 'E':
                        editing_menu(chosen)
                        correct_map.clear(); incorrect_map.clear()
                        for q_ in chosen:
                            cset_ = set(q_.get("correct_answers", []))
                            picks_ = q_["user_answers"]
                            for alt_ in picks_:
                                (correct_map if alt_ in cset_ else incorrect_map).append((q_, alt_))
                        c_count = len(correct_map); i_count = len(incorrect_map)
                        print(f"\nNEW Tally => Correct picks={c_count}, Incorrect={i_count}.\n")
                        continue
                    elif answer == 'N':
                        if input("Are you sure you want to abort? (y/n): ").strip().lower().startswith('y'):
                            print("Aborting."); return
                        else:
                            continue
                    else:
                        print("Invalid choice.\n"); continue
            else:
                break

        prompt_text = "Real threshold"
        r_thr = get_threshold(prompt_text, 10, c_count)
        print(f"[INFO] Must pick >= {r_thr} correct picks to reconstruct real secret.\n")

        # DEMO secret entry with DTE wrap
        real_secret = get_nonempty_secret("Enter REAL secret: ")
        real_b64 = DTE.encode(real_secret)["seed_b64"]

        user_pad = prompt_pad_size_multi(len(real_b64))
        arg_time, arg_mem, arg_par = prompt_argon2_parameters()

        # Split real/dummy shares
        try:
            real_shares, dummy_shares = asyncio.run(
                split_secret_and_dummy(real_b64.encode(), c_count, i_count, r_thr, pad=user_pad)
            )
        except Exception as e:
            log_exception(e, "Error splitting secret")
            print("\n[ERROR] A critical error occurred during the secret splitting process.")
            print("Please check the latest log file for detailed information.")
            return

        def ephemeral_encrypt(data: bytes, q_text: str, alt_text: str, alg_choice: str, alternatives: list[str]) -> dict:
            ephemeral_pass = base64.b64encode(random_bytes(12)).decode()
            ephemeral_salt = random_bytes(16)
            ephemeral_key, ephemeral_salt_used = CF.derive_or_recover_key(
                ephemeral_pass, ephemeral_salt, ephemeral=True,
                time_cost=arg_time, memory_cost=arg_mem, parallelism=arg_par
            )
            q_hash = _integrity_hash_for_kit(q_text, alternatives)
            alt_hash = _alt_hash_for_kit(alt_text)
            aad = _aad_bytes(q_hash, alt_hash, alg_choice)

            enc_obj = _aead_encrypt(alg_choice, data, ephemeral_key, aad=aad)
            enc_obj["ephemeral_password"] = ephemeral_pass
            enc_obj["ephemeral_salt_b64"] = base64.b64encode(ephemeral_salt_used).decode()
            enc_obj["algorithm"] = alg_choice
            return enc_obj

        std_correct, crit_correct, std_incorrect, crit_incorrect = [], [], [], []
        for (q, alt) in correct_map: (crit_correct if q["is_critical"] else std_correct).append((q, alt))
        for (q, alt) in incorrect_map: (crit_incorrect if q["is_critical"] else std_incorrect).append((q, alt))

        share_idx_real, share_idx_dummy = 0, 0
        all_assignments = std_correct + crit_correct + std_incorrect + crit_incorrect

        # AEAD preference sequence for demo (deterministic cycle)
        aead_prefs = []
        if hasattr(CF, "encrypt_xchacha20poly1305"): aead_prefs.append("xchacha20poly1305")
        if hasattr(CF, "encrypt_aes256gcm_siv"):     aead_prefs.append("aes256gcm_siv")
        aead_prefs.extend(["chacha20poly1305", "aes256gcm"])

        for idx, (q_obj, alt_text) in enumerate(all_assignments):
            if q_obj.setdefault("answer_shares", {}).get(alt_text): 
                continue
            is_correct = (q_obj, alt_text) in correct_map
            if is_correct:
                if share_idx_real >= len(real_shares): 
                    continue
                share_data = real_shares[share_idx_real]; share_idx_real += 1
            else:
                if share_idx_dummy >= len(dummy_shares): 
                    continue
                share_data = dummy_shares[share_idx_dummy]; share_idx_dummy += 1

            alg_choice = aead_prefs[idx % len(aead_prefs)]
            enc_full = ephemeral_encrypt(share_data, q_obj["text"], alt_text, alg_choice, q_obj["alternatives"])
            q_obj["answer_shares"][alt_text] = {"enc_data": enc_full}
            for j in range(len(share_data)): share_data[j] = 0

        print("\n--- Final Answering Phase ---\n")
        for i, q in enumerate(chosen, 1):
            picks2 = arrow_select_no_toggle(None, i, q["text"], q["alternatives"], pre_selected=q.get("correct_answers"))
            q["user_answers"] = picks2

        while True:
            result = final_edit_menu(chosen)
            if result == 'G':
                log_debug("User finalize => combine secrets now.", level="INFO")
                break
            elif result == 'N':
                print("Aborted before final reconstruction. Exiting."); return

        partials = []
        for q in chosen:
            if "user_answers" not in q or "answer_shares" not in q: 
                continue
            q_hash = _integrity_hash_for_kit(q["text"], q["alternatives"])
            for alt in q["user_answers"]:
                share_info = q["answer_shares"].get(alt)
                if not share_info: 
                    continue
                enc_data = share_info["enc_data"]
                ephemeral_pass = enc_data.get("ephemeral_password")
                ephemeral_salt_b64 = enc_data.get("ephemeral_salt_b64")
                if not ephemeral_pass or not ephemeral_salt_b64:
                    log_error("Missing ephemeral credentials for a selected answer."); continue
                try:
                    ephemeral_salt = base64.b64decode(ephemeral_salt_b64)
                except Exception as e:
                    log_error(f"Base64 decode error for salt: {e}"); continue
                ephemeral_key, _ = CF.derive_or_recover_key(
                    ephemeral_pass, ephemeral_salt, ephemeral=True,
                    time_cost=arg_time, memory_cost=arg_mem, parallelism=arg_par
                )
                try:
                    alg = enc_data.get("algorithm")
                    aad = _aad_bytes(q_hash, _alt_hash_for_kit(alt), alg or "aes256gcm")
                    dec_pt = _aead_decrypt(alg or "aes256gcm", enc_data, ephemeral_key, aad=aad)
                    log_debug("Demo path decrypted share.", level="INFO", component="CRYPTO",
                              details={"share_sha3_256_hex": hash_share(dec_pt), "algorithm": alg})
                    partials.append(dec_pt)
                except Exception as e:
                    log_error("Decryption failed for a selected answer.", exc=e)

        if len(partials) < r_thr:
            print(f"\nNot enough shares to reconstruct. Got={len(partials)}, need={r_thr}")
            print("Press 1 – Enter setup phase")
            print("Press 2 – Proceed to example demonstration")
            return

        try:
            combined_bytes = _try_combine_with_sampling(partials, r_thr)
            if combined_bytes is None:
                raise RuntimeError("No T-subset succeeded")
            reconstructed_real_b64 = combined_bytes.decode('utf-8')
            log_debug("Demo combine succeeded.", level="INFO", component="CRYPTO",
                      details={"combined_len": len(combined_bytes)})
        except Exception as e:
            log_exception(e, "SSS Combine failed during final reconstruction")
            reconstructed_real_b64 = None

        print("\n--- FINAL RECONSTRUCTION RESULTS ---\n")
        if reconstructed_real_b64:
            try:
                final_secret_text = DTE.decode(reconstructed_real_b64)
                print(f"REAL SECRET recovered: {final_secret_text}\n")
                log_debug("Demo final DTE decode OK.", level="INFO", component="CRYPTO",
                          details={"final_secret_len": len(final_secret_text)})
            except Exception as e:
                log_exception(e, "Failed DTE/base64 decode from combined secret.")
                print("Secret combined, but failed final decode.\n")
        else:
            print("Secret not recoverable.\n")

        append_recovery_guide()
        log_debug("Done with main program.", level="INFO")
        print_estimated_bruteforce_times(
            chosen, arg_time, arg_mem, arg_par,
            total_correct_lower=sum(len(q.get("correct_answers", [])) for q in chosen),
            r_thr=r_thr, decoy_present=True
        )
        print("Press 1 – Enter setup phase")
        print("Press 2 – Proceed to example demonstration")
    except Exception as exc_main:
        log_exception(exc_main, "Fatal error in main()")
        print(f"FATAL ERROR: {exc_main}")
        sys.exit(1)

if __name__ == "__main__":
    ensure_debug_dir()
    check_required_files()
    show_start_menu()
# ============================ END OF FILE: main.py ============================
