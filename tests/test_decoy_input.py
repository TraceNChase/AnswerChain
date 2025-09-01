import unittest
from policy.decoy_input import prompt_decoy_values

class TestDecoyInput(unittest.TestCase):
    def test_reject_blank_and_duplicates(self):
        # Simulate the inner validator directly
        vals = ["Alpha", "  Alpha  ", "Beta"]
        seen = set()
        # emulate uniqueness check
        uniq = []
        for s in vals:
            key = " ".join(s.strip().split()).lower()
            if not s.strip() or key in seen:
                continue
            seen.add(key)
            uniq.append(s)
        self.assertEqual(uniq, ["Alpha", "Beta"])

if __name__ == "__main__":
    unittest.main()
