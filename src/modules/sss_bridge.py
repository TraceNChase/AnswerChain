#!/usr/bin/env python3
# sss_bridge.py — async adapter that keeps your 2-byte length + pad semantics
# and delegates Shamir math to the audited Node CLI.
from __future__ import annotations
import asyncio, json, base64
from pathlib import Path
from typing import List

from modules.debug_utils import log_debug  # existing logger
from modules.security_utils import hash_share  # your helper (unchanged)

# ----- helpers copied from your SSS.py (same behavior) -----
def pack_len(n: int) -> bytes:
    return n.to_bytes(2, "big")

def unpack_len(b: bytes) -> int:
    return int.from_bytes(b, "big")

# Compute filesystem locations relative to this file for robustness
import sys
if getattr(sys, 'frozen', False) or (hasattr(sys, 'argv') and sys.argv[0].endswith('.pyz')):
    # Running from .pyz: bridge is next to the .pyz file
    ROOT_DIR = Path(sys.argv[0]).parent
else:
    # Normal mode: compute relative paths
    MODULE_DIR = Path(__file__).resolve().parent
    SRC_DIR = MODULE_DIR.parent
    ROOT_DIR = SRC_DIR.parent
# **UPDATED** to point to the .cjs file for CommonJS compatibility
BRIDGE_CJS = ROOT_DIR / "bridge" / "sss-bridge.cjs"

def _assert_bridge_exists() -> None:
    if not BRIDGE_CJS.exists():
        raise FileNotFoundError(
            f"Node bridge not found at '{BRIDGE_CJS}'. "
            "Expected layout: <repo_root>\\bridge\\sss-bridge.cjs"
        )

async def _node_call(payload: dict, timeout: float = 15.0) -> dict:
    """Invoke Node CLI with JSON over stdin/out."""
    _assert_bridge_exists()
    proc = await asyncio.create_subprocess_exec(
        "node",
        str(BRIDGE_CJS),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    req = json.dumps(payload).encode("utf-8")
    out, err = await asyncio.wait_for(proc.communicate(input=req), timeout=timeout)

    # Node writes all responses on stdout; stderr indicates an unexpected failure.
    if err:
        try:
            log_debug(
                f"sss-bridge stderr: {err.decode(errors='ignore')}",
                level="WARNING",
                component="CRYPTO",
            )
        except Exception:
            pass

    try:
        resp = json.loads(out.decode("utf-8"))
    except Exception as e:
        raise RuntimeError(f"Invalid bridge response: {e}") from e

    if not resp.get("ok", False):
        raise RuntimeError(f"Bridge error: {resp.get('error','unknown')}")
    return resp

async def sss_split(secret: bytes, shares: int, threshold: int, pad: int = 128) -> List[bytearray]:
    """
    Preserve your semantics:
    - Prepend 2-byte big-endian length
    - Zero pad to 'pad' bytes
    - Call audited split; each share length = pad+1, last byte is x in [1..shares]
    """
    log_debug(
        "sss_split() via node-bridge",
        level="INFO",
        component="CRYPTO",
        details={"secret_len": len(secret), "shares": shares, "threshold": threshold, "pad": pad},
    )

    if shares < threshold:
        raise ValueError("shares < threshold in sss_split")
    if pad < len(secret):
        raise ValueError("pad must >= secret length")

    length_part = pack_len(len(secret))
    extra = pad - 2 - len(secret)
    if extra < 0:
        raise ValueError("pad too small unexpectedly")
    padded = length_part + secret + (b"\x00" * extra)

    resp = await _node_call(
        {
            "cmd": "split",
            "secret_b64": base64.b64encode(padded).decode(),
            "shares": shares,
            "threshold": threshold,
        }
    )

    out: List[bytearray] = []
    for b64 in resp["shares_b64"]:
        raw = base64.b64decode(b64)
        out.append(bytearray(raw))

    try:
        xcoords = [int(s[-1]) for s in out]
        sample_hashes = [hash_share(bytes(s)) for s in out[: min(3, len(out))]]
        log_debug(
            "sss_split() complete.",
            level="INFO",
            component="CRYPTO",
            details={"share_len": (pad + 1), "xcoords": xcoords, "sample_share_hashes": sample_hashes},
        )
    except Exception:
        # Logging should never break the crypto path
        pass

    return out

async def sss_combine(shares: List[bytes]) -> bytes:
    """
    Delegate combine to audited code; then strip 2-byte length and return real secret bytes.
    """
    log_debug(
        "sss_combine() via node-bridge",
        level="INFO",
        component="CRYPTO",
        details={"num_shares": len(shares), "share_len": (len(shares[0]) if shares else None)},
    )

    if not shares:
        raise ValueError("No shares passed to sss_combine")
    length = len(shares[0])
    if any(len(s) != length for s in shares):
        raise ValueError("Inconsistent share length")
    # x uniqueness & equal-length are rechecked by the audited library.

    resp = await _node_call(
        {
            "cmd": "combine",
            "shares_b64": [base64.b64encode(s).decode() for s in shares],
        }
    )

    padded = base64.b64decode(resp["secret_b64"])
    real_len = unpack_len(padded[:2])
    out_bytes = padded[2 : 2 + real_len] if real_len <= (len(padded) - 2) else bytes(padded)

    try:
        log_debug(
            "sss_combine() complete.",
            level="INFO",
            component="CRYPTO",
            details={"reconstructed_len": len(out_bytes), "reconstructed_sha3_256": hash_share(out_bytes)},
        )
    except Exception:
        pass

    return out_bytes

async def sss_combine_batch(shares: List[bytes], sets: List[tuple[int, ...]]) -> list[bytes | None]:
    """
    Batch combine: single Node invocation to reconstruct many subsets.
    Returns a list the same length as sets with bytes or None on failure.
    """
    log_debug(
        "sss_combine_batch() via node-bridge",
        level="INFO",
        component="CRYPTO",
        details={"num_shares": len(shares), "num_sets": len(sets), "share_len": (len(shares[0]) if shares else None)},
    )
    if not shares or not sets:
        return []

    resp = await _node_call(
        {
            "cmd": "combine_batch",
            "shares_b64": [base64.b64encode(s).decode() for s in shares],
            "sets": [list(map(int, idxs)) for idxs in sets],
        }
    )
    out_list: list[bytes | None] = []
    for b64 in resp.get("secrets_b64", []):
        if b64 is None:
            out_list.append(None)
        else:
            padded = base64.b64decode(b64)
            real_len = unpack_len(padded[:2])
            out_bytes = padded[2 : 2 + real_len] if real_len <= (len(padded) - 2) else bytes(padded)
            out_list.append(out_bytes)
    return out_list
