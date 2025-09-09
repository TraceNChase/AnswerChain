################################################################################
# START OF FILE: "ui_utils.py"
################################################################################

"""
FILENAME:
"ui_utils.py"

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
Implements arrow-based selection of answers & toggling question type,
plus editing menus to re-enter or single-edit.
Uses prompt_toolkit for cross-platform interactive UI.
"""

from prompt_toolkit import prompt
from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout.containers import HSplit, Window
from prompt_toolkit.layout.layout import Layout
from prompt_toolkit.widgets import Label
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.styles import Style
from modules.debug_utils import log_debug
from modules.security_utils import sanitize_input, normalize_text
from modules.multiple_choice_pre_picker import create_pre_picker_interface


def arrow_select_clear_on_toggle(stdscr, q_num, q_text, alts,
                                 pre_selected=None, pre_qtype=0, fixed_type=None):
    """
    Allows user to move with UP/DOWN, toggle selections with SPACE,
    optionally toggle question type (CRITICAL vs STANDARD) with 'T', unless fixed_type is set.
    If the user hits ENTER with no selection, show an error and wait.
    """
    q_text = sanitize_input(normalize_text(q_text))
    alts = [sanitize_input(normalize_text(a)) for a in alts]
    
    # Application state
    state = {
        'idx': 0,
        'chosen_mask': [False] * len(alts),
        'qtype': 1 if (fixed_type and fixed_type.upper() == "CRITICAL") else pre_qtype,
        'done': False,
        'result': None,
        'error_msg': ''
    }
    
    toggle_allowed = (fixed_type is None)
    
    if pre_selected:
        for i, a in enumerate(alts):
            if a in pre_selected:
                state['chosen_mask'][i] = True

    def get_formatted_text():
        lines = []
        lines.append(('class:question', f"Q{q_num}. {q_text}"))
        lines.append(('', '\n\n'))
        
        for i, alt in enumerate(alts):
            mark = "[X]" if state['chosen_mask'][i] else "[ ]"
            arrow = "->" if i == state['idx'] else "  "
            style = 'class:selected' if i == state['idx'] else ''
            lines.append((style, f"{arrow} {mark} {chr(65+i)}. {alt}\n"))
        
        mode_str = "CRITICAL" if state['qtype'] == 1 else "STANDARD"
        if not toggle_allowed:
            mode_str += " (fixed)"
        lines.append(('class:mode', f"\nCurrent Type: {mode_str}\n"))
        
        help_ = "UP/DOWN=move, SPACE=toggle"
        if toggle_allowed:
            help_ += ", T=switch type"
        help_ += ", ENTER=confirm, ESC=exit.\n"
        lines.append(('class:help', help_))
        
        if state['error_msg']:
            lines.append(('class:error', f"\n{state['error_msg']}\n"))
        
        return FormattedText(lines)

    # Create layout
    main_window = Window(
        content=FormattedTextControl(
            get_formatted_text,
            focusable=True
        )
    )
    
    layout = Layout(HSplit([main_window]))
    
    # Key bindings
    kb = KeyBindings()
    
    @kb.add('up')
    def _(event):
        if state['idx'] > 0:
            state['idx'] -= 1
    
    @kb.add('down')
    def _(event):
        if state['idx'] < len(alts) - 1:
            state['idx'] += 1
    
    @kb.add(' ')  # Space
    def _(event):
        state['chosen_mask'][state['idx']] = not state['chosen_mask'][state['idx']]
        state['error_msg'] = ''
    
    @kb.add('t')
    @kb.add('T')
    def _(event):
        if toggle_allowed:
            state['chosen_mask'] = [False] * len(alts)
            state['qtype'] = 1 - state['qtype']
            state['error_msg'] = ''
    
    @kb.add('enter')
    def _(event):
        if not any(state['chosen_mask']):
            state['error_msg'] = "Error: Must select at least one."
        else:
            state['done'] = True
            selected = [alts[i] for i, v in enumerate(state['chosen_mask']) if v]
            state['result'] = (selected, state['qtype'])
            event.app.exit()
    
    @kb.add('escape')
    def _(event):
        event.app.exit()

    # Style
    style = Style.from_dict({
        'question': 'bold',
        'selected': 'reverse',
        'mode': 'cyan',
        'help': '',  # Changed from 'dim' to avoid Windows color format issues
        'error': 'red bold',
    })

    try:
        # Create and run application
        app = Application(
            layout=layout,
            key_bindings=kb,
            style=style,
            full_screen=True
        )
        
        app.run()
        if state['result']:
            selected, qtype = state['result']
            mode_str = "CRITICAL" if qtype == 1 else "STANDARD"
            log_debug(f"Q{q_num} picks. Type={mode_str}", level="INFO")
            return selected, qtype
        else:
            # User pressed escape - return empty selection
            return [], state['qtype']
    except Exception as e:
        log_debug(f"UI error in prompt_toolkit: {e}", level="ERROR")
        # Fallback to simple text-based selection
        return _fallback_text_selection(q_num, q_text, alts, pre_selected if pre_selected else [], state['qtype'], toggle_allowed)


def _fallback_text_selection(q_num, q_text, alts, pre_selected, qtype, toggle_allowed):
    """Fallback text-based selection when prompt_toolkit fails"""
    print(f"\nQ{q_num}. {q_text}")
    print("Available options:")
    
    chosen_mask = [False] * len(alts)
    if pre_selected:
        for i, alt in enumerate(alts):
            if alt in pre_selected:
                chosen_mask[i] = True
    
    for i, alt in enumerate(alts):
        mark = "[X]" if chosen_mask[i] else "[ ]"
        print(f"  {i+1}. {mark} {alt}")
    
    print(f"\nCurrent type: {'CRITICAL' if qtype else 'STANDARD'}")
    print("Enter numbers to toggle (e.g., '1 3'), 'T' to toggle type, 'DONE' when finished:")
    
    while True:
        try:
            cmd = input("> ").strip().upper()
            if cmd == 'DONE':
                if any(chosen_mask):
                    break
                else:
                    print("Error: Must select at least one option.")
                    continue
            elif cmd == 'T' and toggle_allowed:
                qtype = 1 - qtype
                chosen_mask = [False] * len(alts)
                print(f"Type changed to: {'CRITICAL' if qtype else 'STANDARD'}")
                continue
            
            # Parse numbers
            nums = []
            for part in cmd.split():
                try:
                    num = int(part)
                    if 1 <= num <= len(alts):
                        nums.append(num - 1)
                except ValueError:
                    pass
            
            for idx in nums:
                chosen_mask[idx] = not chosen_mask[idx]
            
            # Show current selection
            for i, alt in enumerate(alts):
                mark = "[X]" if chosen_mask[i] else "[ ]"
                print(f"  {i+1}. {mark} {alt}")
                
        except (EOFError, KeyboardInterrupt):
            break
    
    selected = [alts[i] for i, v in enumerate(chosen_mask) if v]
    return selected, qtype


def _fallback_simple_selection(q_num, q_text, alts, pre_selected):
    """Fallback simple text-based selection when prompt_toolkit fails"""
    print(f"\nQ{q_num}. {q_text}")
    print("Available options:")
    
    chosen_mask = [False] * len(alts)
    if pre_selected:
        for i, alt in enumerate(alts):
            if alt in pre_selected:
                chosen_mask[i] = True
    
    for i, alt in enumerate(alts):
        mark = "[X]" if chosen_mask[i] else "[ ]"
        print(f"  {i+1}. {mark} {alt}")
    
    print("Enter numbers to toggle (e.g., '1 3'), 'DONE' when finished:")
    
    while True:
        try:
            cmd = input("> ").strip().upper()
            if cmd == 'DONE':
                if any(chosen_mask):
                    break
                else:
                    print("Error: Must select at least one option.")
                    continue
            
            # Parse numbers
            nums = []
            for part in cmd.split():
                try:
                    num = int(part)
                    if 1 <= num <= len(alts):
                        nums.append(num - 1)
                except ValueError:
                    pass
            
            for idx in nums:
                chosen_mask[idx] = not chosen_mask[idx]
            
            # Show current selection
            for i, alt in enumerate(alts):
                mark = "[X]" if chosen_mask[i] else "[ ]"
                print(f"  {i+1}. {mark} {alt}")
                
        except (EOFError, KeyboardInterrupt):
            break
    
    selected = [alts[i] for i, v in enumerate(chosen_mask) if v]
    return selected


def arrow_select_no_toggle(stdscr, q_num, q_text, alts,
                           pre_selected=None):
    """
    Same arrow-based selection but no question-type toggle, for final phase.
    """
    q_text = sanitize_input(normalize_text(q_text))
    alts = [sanitize_input(normalize_text(a)) for a in alts]
    
    # Application state
    state = {
        'idx': 0,
        'chosen_mask': [False] * len(alts),
        'done': False,
        'result': None,
        'error_msg': ''
    }
    
    if pre_selected:
        for i, a in enumerate(alts):
            if a in pre_selected:
                state['chosen_mask'][i] = True

    def get_formatted_text():
        lines = []
        lines.append(('class:question', f"Q{q_num}. {q_text}"))
        lines.append(('', '\n\n'))
        
        for i, alt in enumerate(alts):
            mark = "[X]" if state['chosen_mask'][i] else "[ ]"
            arrow = "->" if i == state['idx'] else "  "
            style = 'class:selected' if i == state['idx'] else ''
            lines.append((style, f"{arrow} {mark} {chr(65+i)}. {alt}\n"))
        
        lines.append(('class:help', "\nUP/DOWN=move, SPACE=toggle, ENTER=confirm, ESC=exit.\n"))
        
        if state['error_msg']:
            lines.append(('class:error', f"\n{state['error_msg']}\n"))
        
        return FormattedText(lines)

    # Create layout
    main_window = Window(
        content=FormattedTextControl(
            get_formatted_text,
            focusable=True
        )
    )
    
    layout = Layout(HSplit([main_window]))
    
    # Key bindings
    kb = KeyBindings()
    
    @kb.add('up')
    def _(event):
        if state['idx'] > 0:
            state['idx'] -= 1
    
    @kb.add('down')
    def _(event):
        if state['idx'] < len(alts) - 1:
            state['idx'] += 1
    
    @kb.add(' ')  # Space
    def _(event):
        state['chosen_mask'][state['idx']] = not state['chosen_mask'][state['idx']]
        state['error_msg'] = ''
    
    @kb.add('enter')
    def _(event):
        if not any(state['chosen_mask']):
            state['error_msg'] = "Error: Must select at least one."
        else:
            state['done'] = True
            selected = [alts[i] for i, v in enumerate(state['chosen_mask']) if v]
            state['result'] = selected
            event.app.exit()
    
    @kb.add('escape')
    def _(event):
        event.app.exit()

    # Style
    style = Style.from_dict({
        'question': 'bold',
        'selected': 'reverse',
        'help': '',  # Changed from 'dim' to avoid Windows color format issues
        'error': 'red bold',
    })

    try:
        # Create and run application
        app = Application(
            layout=layout,
            key_bindings=kb,
            style=style,
            full_screen=True
        )
        
        app.run()
        if state['result']:
            selected = state['result']
            log_debug(f"Q{q_num} final picks", level="INFO")
            return selected
        else:
            # User pressed escape - return empty selection
            return []
    except Exception as e:
        log_debug(f"UI error in prompt_toolkit: {e}", level="ERROR")
        # Fallback to simple text-based selection
        return _fallback_simple_selection(q_num, q_text, alts, pre_selected if pre_selected else [])


def editing_menu(chosen):
    """
    Command-based menu for re-entering or single-editing questions.
    """
    print("\n--- Editing Menu ---")
    print("Press 'E' to re-enter ALL answers.")
    print(f"Or type question #(1..{len(chosen)}) to edit a single. 'N' if done.\n")
    cmd = input("Choice: ").strip().upper()
    if cmd == 'N':
        return True
    if cmd == 'E':
        for i, qdict in enumerate(chosen, 1):
            picks, qtype = arrow_select_clear_on_toggle(
                None, i, qdict["text"], qdict["alternatives"],
                pre_selected=qdict.get("user_answers"),
                pre_qtype=1 if qdict.get("is_critical") else 0,
                fixed_type=qdict.get("force_type")
            )
            qdict["user_answers"] = picks
            if qdict.get("force_type"):
                qdict["is_critical"] = (qdict["force_type"].upper() == "CRITICAL")
            else:
                qdict["is_critical"] = bool(qtype)
        return False
    try:
        num = int(cmd)
        if 1 <= num <= len(chosen):
            qdict = chosen[num - 1]
            picks, qtype = arrow_select_clear_on_toggle(
                None, num, qdict["text"], qdict["alternatives"],
                pre_selected=qdict.get("user_answers"),
                pre_qtype=1 if qdict.get("is_critical") else 0,
                fixed_type=qdict.get("force_type")
            )
            qdict["user_answers"] = picks
            if qdict.get("force_type"):
                qdict["is_critical"] = (qdict["force_type"].upper() == "CRITICAL")
            else:
                qdict["is_critical"] = bool(qtype)
        else:
            print("Invalid question #.")
    except:
        print("Unrecognized cmd.")
    return False


def final_edit_menu(chosen):
    """
    Command-based menu for final pre-generation edits or abort.
    """
    print("\n--- Final Editing Menu ---")
    print("Press 'G' => generate secret. 'E' => re-enter ALL. or # => single. 'N'=>exit\n")
    cmd = input("Your choice: ").strip().upper()
    if cmd in ['G', 'N']:
        return cmd
    if cmd == 'E':
        for i, qdict in enumerate(chosen, 1):
            picks, qtype = arrow_select_clear_on_toggle(
                None, i, qdict["text"], qdict["alternatives"],
                pre_selected=qdict.get("user_answers"),
                pre_qtype=1 if qdict.get("is_critical") else 0,
                fixed_type=qdict.get("force_type")
            )
            qdict["user_answers"] = picks
            if qdict.get("force_type"):
                qdict["is_critical"] = (qdict["force_type"].upper() == "CRITICAL")
            else:
                qdict["is_critical"] = bool(qtype)
        return None
    try:
        num = int(cmd)
        if 1 <= num <= len(chosen):
            qdict = chosen[num - 1]
            picks, qtype = arrow_select_clear_on_toggle(
                None, num, qdict["text"], qdict["alternatives"],
                pre_selected=qdict.get("user_answers"),
                pre_qtype=1 if qdict.get("is_critical") else 0,
                fixed_type=qdict.get("force_type")
            )
            qdict["user_answers"] = picks
            if qdict.get("force_type"):
                qdict["is_critical"] = (qdict["force_type"].upper() == "CRITICAL")
            else:
                qdict["is_critical"] = bool(qtype)
        else:
            print("Invalid question #.")
    except:
        print("Unrecognized cmd.")
    return None

def arrow_select_recovery_mode_enhanced(q_num, q_text, alts, correct_answers, allow_modification=False):
    """
    Enhanced recovery mode selection implementing Objective 1: Correct Answer Pre-Picking.
    
    This function provides an improved interface for the constraint-based multiple choice
    selection workflow specified in Objective 1.
    
    Workflow:
    1. System displays a list of alternatives (multiple-choice)
    2. Correct answers are automatically pre-marked [X]
    3. Incorrect answers remain unmarked [ ]
    4. User navigates using UP/DOWN
    5. User can toggle selections with SPACE if modification is permitted
    6. User confirms with ENTER
    
    Constraints:
    - All answering alternatives are selected
    - Incorrect answers must remain unmarked
    - All-selected state is prohibited
    - All-unselected state is prohibited
    
    Expected Outcome:
    - Users see correct answers already pre-picked
    - Incorrect answers remain visibly unselected
    
    Args:
        q_num: Question number for display
        q_text: Question text to display
        alts: List of all alternative answers
        correct_answers: List of correct answers to pre-select
        allow_modification: Whether to allow user modifications (default: False)
        
    Returns:
        List of selected alternatives
    """
    try:
        result, success = create_pre_picker_interface(
            question_id=q_num,
            question_text=q_text,
            alternatives=alts,
            correct_answers=correct_answers,
            allow_modification=allow_modification
        )
        
        if success:
            log_debug(f"Q{q_num} enhanced recovery picks completed successfully", level="INFO")
            return result
        else:
            log_debug(f"Q{q_num} enhanced recovery picks cancelled by user", level="INFO")
            # Return pre-selected correct answers as fallback
            return correct_answers if correct_answers else []
            
    except Exception as e:
        log_debug(f"Enhanced recovery mode failed: {e}, falling back to original", level="ERROR")
        # Fallback to original implementation
        return arrow_select_recovery_mode(None, q_num, q_text, alts, correct_answers)


def arrow_select_recovery_mode(stdscr, q_num, q_text, alts, correct_answers, pre_selected=None):
    """
    Recovery mode selection with correct answer pre-picking and constraints.
    - Correct answers are automatically pre-marked [X]
    - Incorrect answers remain unmarked [ ]
    - User can navigate but cannot create invalid states
    - All-selected and all-unselected states are prohibited
    """
    q_text = sanitize_input(normalize_text(q_text))
    alts = [sanitize_input(normalize_text(a)) for a in alts]
    correct_set = set(correct_answers) if correct_answers else set()
    
    # Application state
    state = {
        'idx': 0,
        'chosen_mask': [False] * len(alts),
        'done': False,
        'result': None,
        'error_msg': ''
    }
    
    # Pre-select correct answers
    if correct_answers:
        for i, alt in enumerate(alts):
            if alt in correct_answers:
                state['chosen_mask'][i] = True
    elif pre_selected:
        for i, alt in enumerate(alts):
            if alt in pre_selected:
                state['chosen_mask'][i] = True

    def get_formatted_text():
        lines = []
        lines.append(('class:question', f"Q{q_num}. {q_text}"))
        lines.append(('', '\n'))
        lines.append(('class:info', '[Correct answers are pre-selected and locked]\n\n'))
        
        for i, alt in enumerate(alts):
            mark = "[X]" if state['chosen_mask'][i] else "[ ]"
            arrow = "->" if i == state['idx'] else "  "
            
            # Color coding: correct answers in green, others in normal color
            style = 'class:selected' if i == state['idx'] else ''
            if alt in correct_set:
                style += ' class:correct'
            
            lines.append((style, f"{arrow} {mark} {chr(65+i)}. {alt}\n"))
        
        lines.append(('class:help', "\nUP/DOWN=move, ENTER=confirm, ESC=exit.\n"))
        lines.append(('class:constraint', "Constraint: All answering alternatives are selected. Correct answers cannot be changed.\n"))
        
        if state['error_msg']:
            lines.append(('class:error', f"\n{state['error_msg']}\n"))
        
        return FormattedText(lines)

    # Create layout
    main_window = Window(
        content=FormattedTextControl(
            get_formatted_text,
            focusable=True
        )
    )
    
    layout = Layout(HSplit([main_window]))
    
    # Key bindings
    kb = KeyBindings()
    
    @kb.add('up')
    def _(event):
        if state['idx'] > 0:
            state['idx'] -= 1
    
    @kb.add('down')
    def _(event):
        if state['idx'] < len(alts) - 1:
            state['idx'] += 1
    
    @kb.add(' ')  # Space - toggle with constraints
    def _(event):
        # Objective 1: Enforce "All answering alternatives are selected" constraint
        # Correct answers are pre-marked and cannot be unmarked
        # Incorrect answers cannot be marked
        current_alt = alts[state['idx']]
        
        if current_alt in correct_set:
            # Cannot unmark correct answers
            state['error_msg'] = "Error: Cannot unselect correct answers."
            return
        else:
            # Cannot mark incorrect answers
            state['error_msg'] = "Error: Cannot select incorrect answers."
            return
    
    @kb.add('enter')
    def _(event):
        # Objective 1: The workflow requires all correct answers selected by default
        # User can only view but not modify selections
        selected_count = sum(state['chosen_mask'])
        if selected_count == len(correct_set):
            # All correct answers are selected - proceed
            state['done'] = True
            selected = [alts[i] for i, v in enumerate(state['chosen_mask']) if v]
            state['result'] = selected
            event.app.exit()
        else:
            state['error_msg'] = "Error: All correct answers must remain selected."
    
    @kb.add('escape')
    def _(event):
        event.app.exit()

    # Style
    style = Style.from_dict({
        'question': 'bold',
        'info': 'cyan',
        'selected': 'reverse',
        'correct': 'green',
        'help': '',
        'constraint': 'yellow',
        'error': 'red bold',
    })

    try:
        # Create and run application
        app = Application(
            layout=layout,
            key_bindings=kb,
            style=style,
            full_screen=True
        )
        
        app.run()
        if state['result']:
            selected = state['result']
            log_debug(f"Q{q_num} recovery picks", level="INFO")
            return selected
        else:
            # User pressed escape - return pre-selected if available
            return [alts[i] for i, v in enumerate(state['chosen_mask']) if v]
    except Exception as e:
        log_debug(f"UI error in recovery mode: {e}", level="ERROR")
        # Fallback to simple text-based selection
        return _fallback_recovery_selection(q_num, q_text, alts, correct_answers, pre_selected)


def _fallback_recovery_selection(q_num, q_text, alts, correct_answers, pre_selected):
    """Fallback recovery selection when prompt_toolkit fails"""
    print(f"\nQ{q_num}. {q_text}")
    print("[Correct answers are pre-selected and locked]")
    print("Available options:")
    
    chosen_mask = [False] * len(alts)
    correct_set = set(correct_answers) if correct_answers else set()
    
    # Pre-select correct answers
    if correct_answers:
        for i, alt in enumerate(alts):
            if alt in correct_answers:
                chosen_mask[i] = True
    elif pre_selected:
        for i, alt in enumerate(alts):
            if alt in pre_selected:
                chosen_mask[i] = True
    
    for i, alt in enumerate(alts):
        mark = "[X]" if chosen_mask[i] else "[ ]"
        correct_indicator = " (correct)" if alt in correct_set else ""
        print(f"  {i+1}. {mark} {alt}{correct_indicator}")
    
    print("Press ENTER to continue with pre-selected correct answers:")
    print("Constraint: All answering alternatives are selected. Correct answers cannot be changed.")
    
    while True:
        try:
            cmd = input("> ").strip().upper()
            if cmd == '' or cmd == 'DONE':
                # Return the pre-selected correct answers
                return [alts[i] for i, v in enumerate(chosen_mask) if v]
            else:
                print("Constraint: All answering alternatives are selected. Press ENTER to continue.")
        except (KeyboardInterrupt, EOFError):
            return [alts[i] for i, v in enumerate(chosen_mask) if v]

################################################################################
# END OF FILE: "ui_utils.py"
################################################################################
