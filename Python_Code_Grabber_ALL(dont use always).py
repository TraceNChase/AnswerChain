#!/usr/bin/env python3
"""
grab_source.py
Recursive, path-aware source & asset collector.

- Scans ALL files (no extension filter) under:
    * Provided --include-paths (semicolon-separated, relative or absolute), OR
    * The base directory (default: folder containing this script)
- Excludes directory NAMES globally (default: .git, .github plus a few sensible caches)
- Concatenates readable text files into one output.
- Records non-text/binary (or too-large) files in a MANIFEST with path, size, and SHA-256.

USAGE
=====
  py grab_source.py
  py grab_source.py --dry-run
  py grab_source.py --include-paths "AnswerChain;AnswerChain\\src" --exclude-dirs ".git,.github"
  py grab_source.py --max-bytes 1048576 --follow-symlinks
  py grab_source.py --output "AllProjectSources.txt"

Notes:
- Paths can be absolute (e.g., C:\\Users\\...\\AnswerChain) or relative to --base.
- Exclusion matches by directory NAME anywhere in the tree.
"""

import argparse
import sys
import stat
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Set, Tuple, Iterable

# Defaults tuned for your project
DEFAULT_EXCLUDE_DIRS = {
    ".git", ".github",
    ".hg", ".svn", "__pycache__", ".venv", "venv", "env", ".env",
    ".idea", ".vscode", "dist", "build", "out", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".cache"
}

HEADER_RULE = "#" * 120

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Recursively collect all files under project paths.")
    p.add_argument("--base", type=str, default=None,
                   help="Base directory (default: folder containing this script)")
    p.add_argument("--include-paths", type=str, default=None,
                   help="Semicolon-separated list of paths to scan (absolute or relative to --base). "
                        "If omitted, scans --base recursively.")
    p.add_argument("--exclude-dirs", type=str, default=",".join(sorted(DEFAULT_EXCLUDE_DIRS)),
                   help="Comma-separated directory NAMES to exclude (matched anywhere in tree)")
    p.add_argument("--output", type=str, default="AllProjectSources.txt",
                   help="Output file name (default: AllProjectSources.txt) written to --output-dir")
    p.add_argument("--output-dir", type=str, default=None,
                   help="Directory to write the output file (default: --base)")
    p.add_argument("--max-bytes", type=int, default=512_000,
                   help="Max bytes to inline from a single file (default: 512KB). "
                        "Larger files are logged only in MANIFEST.")
    p.add_argument("--dry-run", action="store_true", help="Show what would be scanned, no file writing")
    p.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks when walking directories")
    return p.parse_args()

def normalize_excludes(names_csv: str) -> Set[str]:
    return {n.strip() for n in names_csv.split(",") if n.strip()}

def sha256_file(fp: Path) -> str:
    h = hashlib.sha256()
    try:
        with fp.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"ERROR:{e}"

def is_probably_text(bytes_head: bytes) -> bool:
    # Heuristic: reject if NUL bytes present or too many non-printable characters.
    if b"\x00" in bytes_head:
        return False
    # Allow common whitespace and ASCII; tolerate UTF-8.
    textlike = sum(32 <= b <= 126 or b in (9, 10, 13) for b in bytes_head)
    return textlike / max(1, len(bytes_head)) > 0.85

def walk_paths(paths: List[Path], exclude_names: Set[str], follow_symlinks: bool) -> Iterable[Path]:
    for root in paths:
        if not root.exists():
            continue
        # rglob('**/*') is equivalent to recursive, but we want control over dir skip
        stack = [root]
        seen_dirs = set()
        while stack:
            cur = stack.pop()
            try:
                cur_resolved = cur.resolve(strict=False)
            except Exception:
                cur_resolved = cur
            if cur_resolved in seen_dirs:
                continue
            seen_dirs.add(cur_resolved)

            if cur.is_dir():
                # Skip excluded directories by NAME
                if cur.name in exclude_names and cur != root:
                    continue
                try:
                    for entry in sorted(cur.iterdir(), key=lambda p: str(p).lower()):
                        # If not following symlinks, skip symlinked dirs/files
                        if entry.is_symlink() and not follow_symlinks:
                            continue
                        if entry.is_dir():
                            stack.append(entry)
                        elif entry.is_file():
                            yield entry
                except PermissionError:
                    continue
            elif cur.is_file():
                yield cur

def safe_read_text(fp: Path, max_bytes: int) -> Tuple[str, bool, int]:
    """
    Returns (content, fully_read, size)
    - content is text (utf-8 with replacement) up to max_bytes
    - fully_read indicates whether entire file was inlined
    - size is actual file size in bytes
    """
    try:
        size = fp.stat().st_size
    except Exception:
        size = -1

    head = b""
    try:
        with fp.open("rb") as f:
            head = f.read(min(8192, max_bytes))
    except Exception:
        return ("", False, size)

    if not is_probably_text(head):
        return ("", False, size)

    # If it's text-like, read up to max_bytes
    data = head
    try:
        if size > len(head):
            with fp.open("rb") as f:
                data = f.read(max_bytes)
    except Exception:
        pass

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        # Fallback to latin-1 as last resort
        text = data.decode("latin-1", errors="replace")

    fully = (size >= 0 and size <= max_bytes)
    return (text, fully, size)

def resolve_include_paths(base: Path, include_paths_arg: str) -> List[Path]:
    if not include_paths_arg:
        return [base]
    items = [p.strip() for p in include_paths_arg.split(";") if p.strip()]
    resolved: List[Path] = []
    for item in items:
        p = Path(item)
        if not p.is_absolute():
            p = (base / p).resolve()
        resolved.append(p)
    # Deduplicate while preserving order
    seen = set()
    uniq = []
    for p in resolved:
        if p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq

def main() -> None:
    args = parse_args()
    base = Path(args.base).resolve() if args.base else Path(__file__).resolve().parent
    if not base.exists() or not base.is_dir():
        print(f"[ERROR] Base directory does not exist: {base}")
        sys.exit(2)

    exclude_names = normalize_excludes(args.exclude_dirs)
    include_paths = resolve_include_paths(base, args.include_paths)

    output_dir = Path(args.output_dir).resolve() if args.output_dir else base
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file = output_dir / args.output

    # Build a deterministic list of files
    files = list(walk_paths(include_paths, exclude_names, args.follow_symlinks))
    files = sorted(files, key=lambda p: str(p).lower())

    if args.dry_run:
        print("[DRY-RUN] Base:", base)
        print("[DRY-RUN] Include paths:")
        for p in include_paths:
            print("  -", p)
        print("[DRY-RUN] Excluding dir names:", sorted(exclude_names))
        print("[DRY-RUN] Total files found:", len(files))
        for f in files[:200]:
            print("  ", f)
        if len(files) > 200:
            print(f"  ... and {len(files) - 200} more")
        print("[DRY-RUN] Would write to:", output_file)
        return

    collected: List[str] = []
    manifest: List[str] = []
    total_files = 0
    total_inlined = 0
    total_bytes_inlined = 0
    total_bytes_all = 0

    collected.append(f"{'='*120}\nFULL PROJECT COLLECTION\nBase: {base}\nTimestamp: {timestamp}\n"
                     f"Include paths:\n" + "\n".join(f"  - {p}" for p in include_paths) + "\n"
                     f"Excluded directory names: {sorted(exclude_names)}\n"
                     f"Max inline size per file: {args.max_bytes} bytes\n"
                     f"{'='*120}\n")

    for fp in files:
        total_files += 1
        try:
            st = fp.stat()
            size = st.st_size
        except Exception:
            size = -1

        file_hash = sha256_file(fp)
        rel = str(fp)
        total_bytes_all += size if size >= 0 else 0

        text, fully, _ = safe_read_text(fp, args.max_bytes)

        if text and fully:
            collected.append(
                f"\n{HEADER_RULE}\n# FILE: {rel}\n# SIZE: {size}\n# HASH: {file_hash}\n# TIMESTAMP: {timestamp}\n{HEADER_RULE}\n"
            )
            collected.append(text)
            collected.append(f"\n{HEADER_RULE}\n# END OF FILE: {rel}\n{HEADER_RULE}\n")
            total_inlined += 1
            total_bytes_inlined += size if size >= 0 else 0
        elif text and not fully:
            # Partial inline + mark truncated
            collected.append(
                f"\n{HEADER_RULE}\n# FILE: {rel}\n# SIZE: {size}\n# HASH: {file_hash}\n# TIMESTAMP: {timestamp}\n"
                f"# NOTE: Content truncated to first {args.max_bytes} bytes\n{HEADER_RULE}\n"
            )
            collected.append(text)
            collected.append(f"\n{HEADER_RULE}\n# END OF FILE (TRUNCATED): {rel}\n{HEADER_RULE}\n")
            total_inlined += 1
            total_bytes_inlined += args.max_bytes
            manifest.append(f"TRUNCATED | {rel} | SIZE={size} | HASH={file_hash}")
        else:
            # Binary or unreadable: record in manifest only
            manifest.append(f"BINARY/UNREADABLE | {rel} | SIZE={size} | HASH={file_hash}")

    # Append manifest & summary
    collected.append(f"\n{'='*120}\nMANIFEST (Non-text, unreadable, or truncated files)\n")
    if manifest:
        collected.extend(f"- {line}" for line in manifest)
    else:
        collected.append("- None")

    collected.append(
        f"\n{'='*120}\nSUMMARY\n"
        f"Total Files Found: {total_files}\n"
        f"Files Inlined (text): {total_inlined}\n"
        f"Total Bytes (all files): {total_bytes_all}\n"
        f"Approx Bytes Inlined: {total_bytes_inlined}\n"
        f"Output: {output_file}\n"
        f"{'='*120}\n"
    )

    try:
        output_file.write_text("\n".join(collected), encoding="utf-8")
        print(f"[INFO] Collection written to: {output_file}")
    except Exception as e:
        print(f"[ERROR] Could not write file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
