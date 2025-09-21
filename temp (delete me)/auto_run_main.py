import sys
from pathlib import Path
from unittest.mock import patch

project_root = Path(__file__).resolve().parents[1]
src_dir = project_root / 'src'
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

import main  # noqa: E402

responses = iter([
    '1',    # number of questions to use from example
    '7',    # Shamir threshold (min requirement for selected questions)
    '',     # PAD size -> accept recommended
    '',     # Argon2 parameter mode -> default fast
    '',     # Confirm using default Argon2 parameters
    'y',    # Proceed despite low combinatorial hardness warning
    'n',    # Do not reveal plaintext secret during internal test
    'j',    # Save encrypted configuration
    'test', # Base name for saved files
    '',     # Final prompt to return to menu after saving
    '',     # Extra safety blank input if flow requests another Enter
])


def input_mock(prompt: str = "") -> str:
    try:
        reply = next(responses)
    except StopIteration:
        reply = ''
    # Echo prompt and response so the scripted run remains visible in logs
    if prompt:
        print(f"{prompt}{reply}")
    else:
        print(reply)
    return reply


def getpass_mock(prompt: str = "") -> str:
    if prompt:
        print(prompt, end='')
    print('[auto-secret-entered]')
    return 'SuperSecretValue123'


def arrow_select_clear_on_toggle_mock(_stdscr, q_num, q_text, alts,
                                      pre_selected=None, pre_qtype=0, fixed_type=None):
    selection = list(alts)
    if fixed_type:
        qtype = 1 if fixed_type.upper() == 'CRITICAL' else 0
    else:
        qtype = pre_qtype if pre_selected else 0
    print(f"[auto] Q{q_num} '{q_text}': selecting {len(selection)} alternatives")
    return selection, qtype


def arrow_select_no_toggle_mock(_stdscr, q_num, q_text, alts, pre_selected=None):
    selection = list(pre_selected) if pre_selected else list(alts)
    print(f"[auto] Final picks for Q{q_num} '{q_text}': {selection}")
    return selection


def editing_menu_mock(_chosen):
    print('[auto] Skipping editing menu')
    return True


def final_edit_menu_mock(_chosen):
    print('[auto] Proceeding to generate secret')
    return 'G'


with patch('builtins.input', input_mock), \
     patch('getpass.getpass', getpass_mock), \
     patch('main.arrow_select_clear_on_toggle', arrow_select_clear_on_toggle_mock), \
     patch('main.arrow_select_no_toggle', arrow_select_no_toggle_mock), \
     patch('main.editing_menu', editing_menu_mock), \
     patch('main.final_edit_menu', final_edit_menu_mock):
    main.ensure_debug_dir()
    main.check_required_files()
    main.main()
