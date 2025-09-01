import unittest, hashlib
from pathlib import Path
import sys

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from policy.recovery_policy import decide_output, deterministic_decoy_index  # type: ignore

class TestNoLeakPolicy(unittest.TestCase):
    def test_real_preferred_when_valid(self):
        real = "aGVsbG8="  # "hello"
        text, is_real = decide_output(real, ["dec1"], b"fp")
        self.assertTrue(is_real)
        self.assertEqual(text, "hello")

    def test_decoy_when_invalid_or_missing(self):
        real = "!!!notbase64!!!"
        decoys = ["d1", "d2", "d3"]
        fp = hashlib.sha3_256(b"answers").digest()
        text, is_real = decide_output(real, decoys, fp)
        self.assertFalse(is_real)
        idx = deterministic_decoy_index(fp, len(decoys))
        self.assertEqual(text, decoys[idx])

if __name__ == "__main__":
    unittest.main()
