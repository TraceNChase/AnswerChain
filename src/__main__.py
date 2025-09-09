#!/usr/bin/env python3
"""
Entry point for the AnswerChain .pyz package.
This ensures proper startup flow with the menu interface.
"""

if __name__ == "__main__":
    from main import ensure_debug_dir, check_required_files, show_start_menu
    ensure_debug_dir()
    check_required_files()
    show_start_menu()
