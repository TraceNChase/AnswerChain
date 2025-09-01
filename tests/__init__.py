import sys
from pathlib import Path

# --- Content for tests/__init__.py ---
INIT_PY_CONTENT = """
"""

# --- Content for tests/test_e2e_flow.py ---
E2E_FLOW_PY_CONTENT = """
import unittest, sys, json, tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from src import main as main_app

class TestEndToEndFlow(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        main_app.SAVE_DIR = Path(self.temp_dir.name)
        self.sample_questions = [{"id": 1, "text": "Q1", "alternatives": ["A", "B"], "correct_answers": ["A"]}, {"id": 2, "text": "Q2", "alternatives": ["C", "D"], "correct_answers": ["C"]}]
    def tearDown(self):
        self.temp_dir.cleanup()
    @patch('src.main.getpass.getpass')
    @patch('builtins.input')
    @patch('src.main.curses.wrapper')
    def test_e2e_recover_real_secret(self, mock_curses, mock_input, mock_getpass):
        mock_getpass.return_value = "real"
        mock_input.side_effect = ['1', "decoy", '2', '', 'n', 'test_kit']
        main_app.save_questions(self.sample_questions)
        p = next(main_app.SAVE_DIR.glob("*.json")); kit = json.loads(p.read_text())
        mock_curses.side_effect = [["A"], ["C"]]
        with patch('sys.stdout', new_callable=MagicMock) as mock_stdout:
            main_app.run_recovery_kit_flow(kit, p)
            self.assertIn("real", "".join(c.args[0] for c in mock_stdout.write.call_args_list))
"""

# --- Content for tests/test_failure_cases.py ---
FAILURE_CASES_PY_CONTENT = """
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
"""

# --- Content for tests/test_integration_bridges.py ---
INTEGRATION_BRIDGES_PY_CONTENT = """
import unittest
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from modules import crypto_bridge, sss_bridge

class TestIntegrationBridges(unittest.IsolatedAsyncioTestCase):
    def test_crypto_sha3_256(self):
        result = crypto_bridge.sha3_256(b"hello world")
        self.assertEqual(result.hex(), "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938")
    def test_crypto_aes_gcm_roundtrip(self):
        key, nonce = crypto_bridge.random_bytes(32), crypto_bridge.random_bytes(12)
        decrypted = crypto_bridge.aes_gcm_decrypt(key, nonce, crypto_bridge.aes_gcm_encrypt(key, nonce, b"test", None), None)
        self.assertEqual(b"test", decrypted)
    async def test_sss_roundtrip(self):
        shares = await sss_bridge.sss_split(b"secret", 5, 3)
        self.assertEqual(b"secret", await sss_bridge.sss_combine(shares[:3]))
    async def test_sss_insufficient_shares_fails(self):
        shares = await sss_bridge.sss_split(b"secret", 5, 3)
        with self.assertRaises(RuntimeError):
            await sss_bridge.sss_combine(shares[:2])
"""

# --- Content for tests/test_unit_helpers.py ---
UNIT_HELPERS_PY_CONTENT = """
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
        self.assertEqual(sanitize_input("a\\0b"), "ab")
    def test_decoy_pick_index_is_deterministic(self):
        a = [("q1", "a1"), ("q2", "a2")]
        self.assertEqual(_decoy_pick_index(a, 5), _decoy_pick_index(a, 5))
"""

def create_test_files():
    """Creates the 'tests' directory and populates it with test files."""
    
    # Define the directory for the tests
    tests_dir = Path("tests")
    
    # A dictionary mapping filenames to their content
    files_to_create = {
        "__init__.py": INIT_PY_CONTENT,
        "test_e2e_flow.py": E2E_FLOW_PY_CONTENT,
        "test_failure_cases.py": FAILURE_CASES_PY_CONTENT,
        "test_integration_bridges.py": INTEGRATION_BRIDGES_PY_CONTENT,
        "test_unit_helpers.py": UNIT_HELPERS_PY_CONTENT
    }
    
    # Create the directory if it doesn't exist
    print(f"Checking/Creating directory: {tests_dir}...")
    tests_dir.mkdir(exist_ok=True)
    print("...Done.")
    
    # Loop through the dictionary and write each file
    for filename, content in files_to_create.items():
        file_path = tests_dir / filename
        print(f"Writing file: {file_path}...")
        # Use .strip() to remove leading/trailing whitespace from the content strings
        file_path.write_text(content.strip(), encoding="utf-8")
        print("...Done.")
        
    print("\nAll test files have been created successfully!")

if __name__ == "__main__":
    create_test_files()