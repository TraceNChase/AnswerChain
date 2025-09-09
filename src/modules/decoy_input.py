#!/usr/bin/env python3
# src/policy/decoy_input.py

from __future__ import annotations
from typing import List

def prompt_decoy_count() -> int:
    print("\nHow many decoy secrets do you want to configure? (1..1000)")
    while True:
        raw = input("Decoy count: ").strip()
        try:
            n = int(raw)
            if 1 <= n <= 1000:
                return n
        except Exception:
            pass
        print("Invalid. Enter an integer between 1 and 1000.")

def prompt_decoy_values(n: int) -> List[str]:
    decoys: List[str] = []
    seen_norm = set()
    print("\nEnter each decoy (must be non-blank and unique).")
    for i in range(1, n+1):
        while True:
            s = input(f"Decoy #{i}: ").strip()
            if not s:
                print("Decoy cannot be blank.")
                continue
            key = " ".join(s.split()).lower()
            if key in seen_norm:
                print("Duplicate decoy. Enter a unique value.")
                continue
            seen_norm.add(key)
            decoys.append(s)
            break
    return decoys
