# grab_source.py
# Robust, path-agnostic source collector that mirrors "non-recursive per directory" behavior
# Place this file at your project root (e.g., ...\AnswerChain) and run:
#   py grab_source.py
#
# Options:
# --base BASE_DIR           Base directory to start from (default: this script's folder)
# --max-depth N             Directory walk depth (default: 2; -1 means unlimited)
# --exts .py,.js            Comma-separated list of file extensions to include
# --exclude-dirs names      Comma-separated dir names to exclude (name-only match)
# --output-dir PATH         Where to write the output file (default: BASE_DIR)
# --include-dirs paths      Comma-separated directories to scan ONLY (non-recursive); relative to base or absolute
# --dry-run                 Show what would be scanned, but do not write output

import argparse
import hashlib
import os
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Set

DEFAULT_EXTS = {".py", ".js"}
DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env", ".env",
    ".idea", ".vscode", "dist", "build", "out", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".cache"
}

HEADER_RULE = "#" * 120

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Collect source files by scanning directories up to a max depth and concatenating files found directly in each visited directory."
    )
    p.add_argument(
        "--base", type=str, default=None,
        help="Base directory (default: folder containing this script)",
    )
    p.add_argument(
        "--max-depth", type=int, default=2,
        help="Max directory depth to traverse from base (default: 2). Use -1 for unlimited.",
    )
    p.add_argument(
        "--exts", type=str, default=",".join(sorted(DEFAULT_EXTS)),
        help="Comma-separated file extensions to include (e.g., .py,.js,.ts)",
    )
    p.add_argument(
        "--exclude-dirs", type=str, default=",".join(sorted(DEFAULT_EXCLUDE_DIRS)),
        help="Comma-separated directory NAMES to exclude (matched by name only).",
    )
    p.add_argument(
        "--output-dir", type=str, default=None,
        help="Directory to write the output file (default: base directory).",
    )
    # ✨ NEW: allow explicitly listing which directories to scan (non-recursive)
    p.add_argument(
        "--include-dirs", type=str, default=None,
        help="Comma-separated directories to scan ONLY (non-recursive); relative to base or absolute.",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Print summary of what would be scanned and exit without writing output.",
    )
    return p.parse_args()

def normalize_exts(ext_list: str) -> Set[str]:
    exts = set()
    for raw in ext_list.split(","):
        s = raw.strip()
        if not s:
            continue
        if not s.startswith("."):
            s = "." + s
        exts.add(s.lower())
    return exts

def normalize_excludes(names_csv: str) -> Set[str]:
    return {n.strip() for n in names_csv.split(",") if n.strip()}

def calculate_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

def bfs_visit_dirs(base: Path, max_depth: int, exclude_names: Set[str]) -> Iterable[Path]:
    """
    Breadth-first traversal from base. Yields each directory visited (including base).
    Only visits up to 'max_depth' edges away from base; -1 means unlimited depth.
    Excludes directories whose name is in exclude_names (name-only check).
    """
    visited: List[Path] = []
    q = deque([(base, 0)])
    seen = set()

    while q:
        cur, depth = q.popleft()
        cur_resolved = cur.resolve()
        if cur_resolved in seen:
            continue
        seen.add(cur_resolved)

        if not cur.exists() or not cur.is_dir():
            continue

        visited.append(cur)

        # If at depth limit (and not unlimited), don't enqueue children
        if max_depth != -1 and depth >= max_depth:
            continue

        try:
            for entry in cur.iterdir():
                if entry.is_dir():
                    if entry.name in exclude_names:
                        continue
                    q.append((entry, depth + 1))
        except PermissionError:
            # Skip directories we cannot access
            continue

    # Yield in a stable, sorted order (by path string)
    for d in sorted(visited, key=lambda p: str(p).lower()):
        yield d

def scan_files_directly_under(directory: Path, code_exts: Set[str]) -> List[Path]:
    """Return files directly in 'directory' whose extension is in code_exts (case-insensitive). Does not recurse."""
    files: List[Path] = []
    try:
        for f in directory.iterdir():
            if f.is_file() and f.suffix.lower() in code_exts:
                files.append(f)
    except PermissionError:
        pass
    return sorted(files, key=lambda p: str(p).lower())

def include_file(file_path: Path, collected_content: List[str], timestamp: str) -> int:
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"[WARNING] Could not read {file_path}: {e}")
        return 0

    file_hash = calculate_hash(content)
    collected_content.append(
        f"\n{HEADER_RULE}\n# FILE: {file_path}\n# HASH: {file_hash}\n# TIMESTAMP: {timestamp}\n{HEADER_RULE}\n"
    )
    collected_content.append(content)
    collected_content.append(f"\n{HEADER_RULE}\n# END OF FILE: {file_path}\n{HEADER_RULE}\n")
    return len(content)

def _parse_include_dirs_arg(raw: str) -> List[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]

def _resolve_dirs(base: Path, raw_dirs: List[str]) -> List[Path]:
    out: List[Path] = []
    seen: Set[Path] = set()
    for d in raw_dirs:
        p = Path(d)
        p = (base / p).resolve() if not p.is_absolute() else p.resolve()
        if p.exists() and p.is_dir() and p not in seen:
            out.append(p)
            seen.add(p)
        else:
            print(f"[WARNING] Skipping missing/non-directory path: {p}")
    return out

def _auto_dirs_for_answerchain(base: Path) -> List[Path]:
    """
    If running at ...\\AnswerChain and the four target dirs exist, use them by default (non-recursive).
    This keeps behavior zero-config for your setup, while remaining generic elsewhere.
    """
    candidates = [base / "bridge",
                  base / "bridge" / "utils",
                  base / "src",
                  base / "src" / "modules"]
    if all(p.exists() and p.is_dir() for p in candidates):
        return [p.resolve() for p in candidates]
    return []

def main() -> None:
    args = parse_args()

    base = Path(args.base).resolve() if args.base else Path(__file__).resolve().parent
    if not base.exists() or not base.is_dir():
        print(f"[ERROR] Base directory does not exist or is not a directory: {base}")
        return

    code_exts = normalize_exts(args.exts)
    exclude_names = normalize_excludes(args.exclude_dirs)

    # Ensure output goes to the same folder by default (your requirement)
    output_dir = Path(args.output_dir).resolve() if args.output_dir else base

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"all_source_files_{timestamp}.txt"

    # Decide WHICH directories to scan (non-recursive inside each):
    dirs_to_scan: List[Path]
    if args.include_dirs:
        # Explicit list provided → ONLY scan these
        include_list = _parse_include_dirs_arg(args.include_dirs)
        dirs_to_scan = _resolve_dirs(base, include_list)
    else:
        # Zero-config for your AnswerChain layout (bridge, bridge/utils, src, src/modules)
        auto = _auto_dirs_for_answerchain(base)
        if auto:
            dirs_to_scan = auto
        else:
            # Fallback: original BFS traversal
            dirs_to_scan = list(bfs_visit_dirs(base, args.max_depth, exclude_names))

    if args.dry_run:
        print("[DRY-RUN] Would scan these directories (non-recursive per directory):")
        for d in dirs_to_scan:
            print(" -", d)
        print(f"[DRY-RUN] Extensions: {sorted(code_exts)}")
        print(f"[DRY-RUN] Excluded dir names: {sorted(exclude_names)}")
        print(f"[DRY-RUN] Output file would be: {output_file}")
        return

    collected_content: List[str] = []
    total_chars = 0
    total_files = 0

    collected_content.append(
        f"{'=' * 120}\n"
        f"SOURCE CODE COLLECTION (directories listed below; files taken directly under each dir only)\n"
        f"Base: {base}\n"
        f"Max Depth: {args.max_depth}\n"
        f"Extensions: {', '.join(sorted(code_exts))}\n"
        f"Excluded dir names: {', '.join(sorted(exclude_names))}\n"
        f"Timestamp: {timestamp}\n"
        f"{'=' * 120}\n"
    )

    for d in dirs_to_scan:
        files = scan_files_directly_under(d, code_exts)
        for file_path in files:
            added = include_file(file_path, collected_content, timestamp)
            if added > 0:
                total_chars += added
                total_files += 1

    collected_content.append(
        f"\n{'=' * 120}\n"
        f"SUMMARY\n"
        f"Total Files: {total_files}\n"
        f"Total Characters: {total_chars}\n"
        f"Timestamp: {timestamp}\n"
        f"Visited Dirs: {len(dirs_to_scan)}\n"
        f"Output: {output_file}\n"
        f"{'=' * 120}\n"
    )

    try:
        output_file.write_text("\n".join(collected_content), encoding="utf-8")
        print(f"[INFO] Source contents saved to: {output_file}")
    except Exception as e:
        print(f"[ERROR] Could not write output file: {e}")

if __name__ == "__main__":
    main()
