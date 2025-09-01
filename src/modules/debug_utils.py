#!/usr/bin/env python3
"""
FILENAME:
"debug_utils.py"

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

import os
import json
import uuid
import inspect
import threading
import shutil
import time
import traceback
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.resolve()
DEBUG_COLLECTION_DIR = BASE_DIR / "logs" / "debug_logs"
DEBUG_COLLECTION_DIR.mkdir(parents=True, exist_ok=True)

RUN_ID = str(uuid.uuid4())

VERBOSITY_LEVELS = {
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50
}
LOG_VERBOSITY = os.environ.get("LOG_VERBOSITY", "DEBUG").upper()
CURRENT_VERBOSITY = VERBOSITY_LEVELS.get(LOG_VERBOSITY, 10)

DEBUG_FILE_JSON = None
DEBUG_FILE_TXT = None
log_lock = threading.Lock()


def get_next_log_counter() -> int:
    """
    Find next incremental integer for debug file naming.
    """
    counter = 1
    for file in DEBUG_COLLECTION_DIR.iterdir():
        if file.is_file() and file.name.startswith("debug_info") and file.name.endswith(".json"):
            try:
                cor = file.name.replace("debug_info", "").replace(".json", "")
                num_part = cor.split("_", maxsplit=1)[0]
                n = int(num_part)
                if n >= counter:
                    counter = n + 1
            except:
                pass
    return counter


def get_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def archive_all_existing_logs():
    """
    Move all existing debug_info .json and .txt logs from debug_logs/ into debug_logs/archive/.
    """
    arch = DEBUG_COLLECTION_DIR / "archive"
    arch.mkdir(exist_ok=True)
    
    for f in DEBUG_COLLECTION_DIR.iterdir():
        if f.is_file() and f.name.startswith("debug_info") and f.suffix in [".json", ".txt"]:
            # Move everything into archive
            shutil.move(str(f), str(arch / f.name))


def ensure_debug_dir():
    """
    On each program start:
      1) Move all existing .json/.txt logs to `archive/`
      2) Create brand-new JSON/TXT debug log files for this run
    """
    global DEBUG_FILE_JSON, DEBUG_FILE_TXT

    # 1) Archive *all* existing logs so only new logs remain
    archive_all_existing_logs()

    # 2) Prepare brand-new log files for this run
    c = get_next_log_counter()
    ts = get_timestamp()
    DEBUG_FILE_JSON = DEBUG_COLLECTION_DIR / f"debug_info{c}_{ts}.json"
    DEBUG_FILE_TXT  = DEBUG_COLLECTION_DIR / f"debug_info{c}_{ts}.txt"

    # Write initial record
    start_entry = {
        "timestamp": datetime.now().isoformat(),
        "run_id": RUN_ID,
        "component": "SYSTEM",
        "level": "INFO",
        "message": "Start new run",
        "details": {"event": "Run Initialization"}
    }
    with log_lock:
        with open(DEBUG_FILE_JSON, "a", encoding="utf-8") as jf, open(DEBUG_FILE_TXT, "a", encoding="utf-8") as tf:
            jf.write(json.dumps(start_entry, indent=2) + "\n")
            tf.write(f"[{start_entry['timestamp']}] [INFO] [SYSTEM] Start new run (run_id={RUN_ID})\n")

    print(f"[DEBUG] Logging to JSON: {DEBUG_FILE_JSON}")
    print(f"[DEBUG] Logging to TXT : {DEBUG_FILE_TXT}")


def _write_log_json(entry: dict):
    with open(DEBUG_FILE_JSON, "a", encoding="utf-8") as jf:
        jf.write(json.dumps(entry, indent=2) + "\n")


def _write_log_txt(entry: dict):
    timestamp = entry.get("timestamp", "N/A")
    lvl = entry.get("level", "N/A")
    comp = entry.get("component", "N/A")
    caller = entry.get("caller", {})
    file_ = caller.get("file", "?")
    func_ = caller.get("function", "?")
    line_ = caller.get("line", "?")
    msg = entry.get("message", "")
    details = entry.get("details", {})
    ev = ""
    if "event" in details:
        ev = f" (event={details['event']})"
    line_txt = f"[{timestamp}] [{lvl}] [{comp}] {file_}:{func_}:{line_}{ev} - {msg}\n"

    with open(DEBUG_FILE_TXT, "a", encoding="utf-8") as tf:
        tf.write(line_txt)


def _do_log(level, component, msg, details=None):
    if details is None:
        details = {}
    nl = VERBOSITY_LEVELS.get(level.upper(), 10)
    if nl < CURRENT_VERBOSITY:
        return

    with log_lock:
        cf = inspect.currentframe().f_back
        entry = {
            "timestamp": datetime.now().isoformat(),
            "run_id": RUN_ID,
            "level": level.upper(),
            "component": component,
            "caller": {
                "file": os.path.basename(cf.f_code.co_filename),
                "function": cf.f_code.co_name,
                "line": cf.f_lineno
            },
            "message": msg,
            "details": details
        }
        _write_log_json(entry)
        _write_log_txt(entry)


def log_debug(msg: str, level="DEBUG", component="GENERAL", details=None):
    _do_log(level, component, msg, details)


def log_crypto_event(operation: str,
                     algorithm: str = None,
                     mode: str = None,
                     ephemeral_key: bytes = None,
                     argon_params: dict = None,
                     key_derived_bytes: bytes = None,
                     details: dict = None,
                     ephemeral: bool = False):
    if details is None:
        details = {}
    crypto_info = {
        "operation": operation,
        "algorithm": algorithm,
        "mode": mode,
        "ephemeral": ephemeral
    }
    if ephemeral_key is not None:
        import base64
        crypto_info["key_b64"] = base64.b64encode(ephemeral_key).decode()
    if key_derived_bytes is not None:
        import base64
        crypto_info["derived_key_b64"] = base64.b64encode(key_derived_bytes).decode()
    if argon_params:
        crypto_info["Argon2_Parameters"] = argon_params

    details["crypto_details"] = crypto_info
    _do_log("INFO", "CRYPTO", "Crypto operation", details)


def log_error(msg: str, exc: Exception = None, details=None):
    if details is None:
        details = {}
    if exc is not None:
        details["exception_type"] = type(exc).__name__
        details["exception_str"] = str(exc)
    _do_log("ERROR", "GENERAL", msg, details)


def log_exception(exc: Exception, msg: str = "Unhandled exception"):
    tb_str = traceback.format_exc()
    details = {
        "exception_type": type(exc).__name__,
        "exception_str": str(exc),
        "traceback": tb_str
    }
    _do_log("ERROR", "GENERAL", msg, details)


def start_timer() -> float:
    return time.perf_counter()


def end_timer(st: float) -> float:
    return (time.perf_counter() - st) * 1000.0


def append_recovery_guide():
    guide_lines = [
        "-------------------- MANUAL DECRYPTION GUIDE --------------------",
        "1. Identify correct standard & critical picks and gather ephemeral-encrypted partials.",
        "2. Decrypt each 95% chunk and 5% chunk (or single 100% chunk). Combine => full share.",
        "3. Provide enough real shares to sss_combine() => base64-decode final secret.",
        "-----------------------------------------------------------------"
    ]
    gjson = {"manual_decryption_guide": guide_lines}
    with log_lock:
        with open(DEBUG_FILE_JSON, "a", encoding="utf-8") as jf:
            jf.write(json.dumps(gjson, indent=2) + "\n")
        with open(DEBUG_FILE_TXT, "a", encoding="utf-8") as tf:
            for line in guide_lines:
                tf.write(line + "\n")
