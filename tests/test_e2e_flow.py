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
