import unittest, base64, json
from pathlib import Path
import sys

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from modules.crypto_bridge import _unb64u  # type: ignore

class TestPadding(unittest.TestCase):
    def test_unb64u_restores_padding(self):
        data = {"ok": True, "hello": "world"}
        encoded = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
        out = json.loads(_unb64u(encoded).decode())
        self.assertEqual(out["hello"], "world")

if __name__ == "__main__":
    unittest.main()
