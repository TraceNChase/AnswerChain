################################################################################
# START OF FILE: "security_utils.py"
################################################################################

"""
FILENAME:
"security_utils.py"

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
Basic text normalization, share hashing with SHA3-256, etc.
Now includes question/answer hashing for Q&A sets.
"""

import unicodedata
import hashlib


def normalize_text(t: str) -> str:
    """
    Normalize text to NFKC, limiting length to 256 chars.
    """
    return unicodedata.normalize('NFKC', t)[:256]


def sanitize_input(t: str) -> str:
    """
    Remove null chars from the input.
    """
    return ''.join(ch for ch in t if ch not in "\0")


def validate_question(q) -> bool:
    """
    Check if a question dict has 'text', 'alternatives', 'correct_answers'.
    """
    if not isinstance(q, dict):
        return False
    if "text" not in q or "alternatives" not in q:
        return False
    if not isinstance(q["text"], str):
        return False
    if not isinstance(q["alternatives"], list):
        return False
    if "correct_answers" not in q:
        q["correct_answers"] = []
    return True


def hash_share(data: bytes) -> str:
    """
    SHA3-256 hash (hex) of a share's byte data.
    """
    return hashlib.sha3_256(data).hexdigest()


def verify_share_hash(data: bytes, expected: str) -> bool:
    """
    Verify the share's data matches the expected SHA3-256 hex digest.
    """
    return hashlib.sha3_256(data).hexdigest() == expected


def hash_question_and_answers(qdict: dict) -> str:
    """
    Create a stable SHA3-256 hash from:
    - question text
    - sorted alternatives
    - sorted correct_answers
    """
    text = qdict["text"]
    alt_list = sorted(qdict["alternatives"])
    correct_list = sorted(qdict["correct_answers"])
    block = text + "\n" + "\n".join(alt_list) + "\n" + "|".join(correct_list)
    return hashlib.sha3_256(block.encode("utf-8")).hexdigest()

################################################################################
# END OF FILE: "security_utils.py"
################################################################################
