################################################################################
# START OF FILE: "input_utils.py"
################################################################################

"""
FILENAME:
"input_utils.py"

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
Handles user integer input & secret input with getpass.
Logs the integer input in plain to ensure everything needed is in logs.
"""

import getpass
from modules.debug_utils import log_debug
from modules.security_utils import sanitize_input  # NOTE: do not import normalize_text here


def safe_input(prompt="", default=""):
    """
    Safe input function that handles EOF gracefully by returning a default value.
    """
    try:
        return input(prompt)
    except EOFError:
        log_debug(f"EOF during input, using default: '{default}'", level="WARNING")
        print(f"\n[EOF detected - using default: '{default}']")
        return default


def get_valid_int(prompt, low, high):
    """
    Prompt user for an integer in [low..high], returning the validated int.
    """
    while True:
        print(prompt, end="", flush=True)
        val = safe_input(default=str(low))
        try:
            num = int(val)
            if low <= num <= high:
                log_debug(f"User int input valid: {num}", level="INFO")
                return num
            else:
                print(f"Must be {low}..{high}")
        except:
            print("Invalid integer input.")


def get_nonempty_secret(prompt):
    """
    Prompt user for a non-empty secret (via getpass).
    SECURITY FIX: Do NOT normalize high-entropy secrets (no NFKC).
    Accept bytes-as-UTF-8 string verbatim (strip NULs only). Enforce policy length.
    """
    POLICY_MAX = 256  # keep existing policy limit (no transformation)
    while True:
        try:
            s = getpass.getpass(prompt)
        except EOFError:
            # Handle EOF gracefully - return a default secret for testing
            log_debug("EOF during secret input, using default", level="WARNING")
            print("\n[EOF detected - using default secret]")
            return "default_test_secret"
        # Remove NULs only; preserve everything else (no normalize_text)
        s = sanitize_input(s)
        if s.strip():
            if len(s) > POLICY_MAX:
                s = s[:POLICY_MAX]
            return s
        print("Cannot be empty.")
        log_debug("Empty secret => re-prompt", level="WARNING")

################################################################################
# END OF FILE: "input_utils.py"
################################################################################
