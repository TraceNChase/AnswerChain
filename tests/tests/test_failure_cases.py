import unittest, sys
from pathlib import Path
from unittest.mock import patch, MagicMock

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from src import main as main_app
from modules import crypto_bridge

class TestFailureCases(unittest.TestCase):
    def test_panic_tampered_ciphertext(self):
        key, nonce = crypto_bridge.random_bytes(32), crypto_bridge.random_bytes(12)
        ciphertext = bytearray(crypto_bridge.aes_gcm_encrypt(key, nonce, b"data", None))
        ciphertext[5] ^= 1
        with self.assertRaises(RuntimeError):
            crypto_bridge.aes_gcm_decrypt(key, nonce, bytes(ciphertext), None)
    @patch('src.main.curses.wrapper', return_value=[["A"]])
    def test_panic_kit_missing_key(self, mock_curses):
        kit = {"questions": [], "encrypted_shares": {}}
        with patch('sys.stdout', new_callable=MagicMock) as mock_stdout:
            main_app.run_recovery_kit_flow(kit, Path("dummy.json"))
            self.assertIn("ERROR: Kit structure invalid", mock_stdout.write.call_args_list[0].args[0])