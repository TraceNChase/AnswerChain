import unittest
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from main import _policy_min_threshold, _aad_bytes, _decoy_pick_index
from modules.security_utils import normalize_text, sanitize_input

class TestUnitHelpers(unittest.TestCase):
    def test_policy_min_threshold(self):
        self.assertEqual(_policy_min_threshold(10), 8)
    def test_aad_bytes_format(self):
        self.assertEqual(_aad_bytes("q", "a", "alg", 3), b"q|a|alg|3")
    def test_normalize_text(self):
        self.assertEqual(normalize_text("ＨＥＬＬＯ"), "HELLO")
    def test_sanitize_input(self):
        self.assertEqual(sanitize_input("a\0b"), "ab")
    def test_decoy_pick_index_is_deterministic(self):
        a = [("q1", "a1"), ("q2", "a2")]
        self.assertEqual(_decoy_pick_index(a, 5), _decoy_pick_index(a, 5))