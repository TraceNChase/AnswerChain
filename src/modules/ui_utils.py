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
"""

import curses
from modules.debug_utils import log_debug
from modules.security_utils import sanitize_input, normalize_text


def arrow_select_clear_on_toggle(stdscr, q_num, q_text, alts,
                                 pre_selected=None, pre_qtype=0, fixed_type=None):
    """
    Allows user to move with UP/DOWN, toggle selections with SPACE,
    optionally toggle question type (CRITICAL vs STANDARD) with 'T', unless fixed_type is set.
    If the user hits ENTER with no selection, show an error and wait.
    """
    curses.curs_set(0)
    q_text = sanitize_input(normalize_text(q_text))
    alts = [sanitize_input(normalize_text(a)) for a in alts]
    idx = 0
    chosen_mask = [False] * len(alts)
    toggle_allowed = (fixed_type is None)
    qtype = 1 if (fixed_type and fixed_type.upper() == "CRITICAL") else pre_qtype

    if pre_selected:
        for i, a in enumerate(alts):
            if a in pre_selected:
                chosen_mask[i] = True

    while True:
        stdscr.clear()
        stdscr.addstr(f"Q{q_num}. {q_text}\n\n")
        for i, alt in enumerate(alts):
            mark = "[X]" if chosen_mask[i] else "[ ]"
            arrow = "->" if i == idx else "  "
            stdscr.addstr(f"{arrow} {mark} {chr(65+i)}. {alt}\n")
        mode_str = "CRITICAL" if qtype == 1 else "STANDARD"
        if not toggle_allowed:
            mode_str += " (fixed)"
        stdscr.addstr(f"\nCurrent Type: {mode_str}\n")
        help_ = "UP/DOWN=move, SPACE=toggle"
        if toggle_allowed:
            help_ += ", T=switch type"
        help_ += ", ENTER=confirm.\n"
        stdscr.addstr(help_)

        key = stdscr.getch()
        if key == curses.KEY_UP and idx > 0:
            idx -= 1
        elif key == curses.KEY_DOWN and idx < len(alts) - 1:
            idx += 1
        elif key == ord(' '):
            chosen_mask[idx] = not chosen_mask[idx]
        elif toggle_allowed and key in [ord('t'), ord('T')]:
            # switching type resets selections
            chosen_mask = [False] * len(alts)
            qtype = 1 - qtype
        elif key == ord('\n'):
            if not any(chosen_mask):
                stdscr.addstr("\nError: Must select at least one.\n")
                stdscr.refresh()
                curses.napms(1500)
            else:
                break

    selected = [alts[i] for i, v in enumerate(chosen_mask) if v]
    mode_str = "CRITICAL" if qtype == 1 else "STANDARD"
    log_debug(f"Q{q_num} picks. Type={mode_str}", level="INFO")
    return selected, qtype


def arrow_select_no_toggle(stdscr, q_num, q_text, alts,
                           pre_selected=None):
    """
    Same arrow-based selection but no question-type toggle, for final phase.
    """
    curses.curs_set(0)
    q_text = sanitize_input(normalize_text(q_text))
    alts = [sanitize_input(normalize_text(a)) for a in alts]
    idx = 0
    chosen_mask = [False] * len(alts)
    if pre_selected:
        for i, a in enumerate(alts):
            if a in pre_selected:
                chosen_mask[i] = True

    while True:
        stdscr.clear()
        stdscr.addstr(f"Q{q_num}. {q_text}\n\n")
        for i, alt in enumerate(alts):
            mark = "[X]" if chosen_mask[i] else "[ ]"
            arrow = "->" if i == idx else "  "
            stdscr.addstr(f"{arrow} {mark} {chr(65+i)}. {alt}\n")
        stdscr.addstr("\nUP/DOWN=move, SPACE=toggle, ENTER=confirm.\n")

        key = stdscr.getch()
        if key == curses.KEY_UP and idx > 0:
            idx -= 1
        elif key == curses.KEY_DOWN and idx < len(alts) - 1:
            idx += 1
        elif key == ord(' '):
            chosen_mask[idx] = not chosen_mask[idx]
        elif key == ord('\n'):
            if not any(chosen_mask):
                stdscr.addstr("\nError: Must select at least one.\n")
                stdscr.refresh()
                curses.napms(1500)
            else:
                break

    selected = [alts[i] for i, v in enumerate(chosen_mask) if v]
    log_debug(f"Q{q_num} final picks", level="INFO")
    return selected


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
        import curses
        for i, qdict in enumerate(chosen, 1):
            picks, qtype = curses.wrapper(
                lambda s: arrow_select_clear_on_toggle(
                    s, i, qdict["text"], qdict["alternatives"],
                    pre_selected=qdict.get("user_answers"),
                    pre_qtype=1 if qdict.get("is_critical") else 0,
                    fixed_type=qdict.get("force_type")
                )
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
            import curses
            qdict = chosen[num - 1]
            picks, qtype = curses.wrapper(
                lambda s: arrow_select_clear_on_toggle(
                    s, num, qdict["text"], qdict["alternatives"],
                    pre_selected=qdict.get("user_answers"),
                    pre_qtype=1 if qdict.get("is_critical") else 0,
                    fixed_type=qdict.get("force_type")
                )
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
        import curses
        for i, qdict in enumerate(chosen, 1):
            picks, qtype = curses.wrapper(
                lambda s: arrow_select_clear_on_toggle(
                    s, i, qdict["text"], qdict["alternatives"],
                    pre_selected=qdict.get("user_answers"),
                    pre_qtype=1 if qdict.get("is_critical") else 0,
                    fixed_type=qdict.get("force_type")
                )
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
            import curses
            qdict = chosen[num - 1]
            picks, qtype = curses.wrapper(
                lambda s: arrow_select_clear_on_toggle(
                    s, num, qdict["text"], qdict["alternatives"],
                    pre_selected=qdict.get("user_answers"),
                    pre_qtype=1 if qdict.get("is_critical") else 0,
                    fixed_type=qdict.get("force_type")
                )
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

################################################################################
# END OF FILE: "ui_utils.py"
################################################################################
