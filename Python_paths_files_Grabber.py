import os
import re
from datetime import datetime

def export_tree_grouped_complete(root_path, dest_path):
    """
    Walk `root_path` (including ALL subfolders, including hidden items) and write a text file where
    each folder is shown followed by:
      - the NAMES of all *immediate subfolders* in that folder
      - the NAMES of all *files* directly in that folder

    The output file is created in `dest_path` and named:
        "ALL paths <root_path> Including ALL subsfolders.txt"
    (Windows-invalid filename characters are replaced with underscores.)

    Notes:
      - Symlinked directories are followed and de-duplicated by real path to avoid infinite loops.
      - Permission errors are recorded under an ERRORS section at the end (script continues).
    """
    os.makedirs(dest_path, exist_ok=True)

    # Build the requested filename and make it Windows-safe
    base_name = f"ALL paths {root_path} Including ALL subsfolders"
    safe_name = re.sub(r'[<>:\"/\\\\|?*]', '_', base_name).strip() + ".txt"
    out_file = os.path.join(dest_path, safe_name)

    total_folders = 0
    total_files = 0
    total_subfolders = 0

    # Storage for stable, sorted output
    records = []  # list of (dirpath, subfolders[], files[])
    errors = []

    # Track visited real paths to avoid cycles when following links
    visited_dirs = set()

    # We'll pass an onerror handler to capture permission errors from os.walk
    def onerr(e):
        errors.append(str(e))

    # Use topdown=True so we can prune cycles by editing dirnames in place
    for dirpath, dirnames, filenames in os.walk(root_path, topdown=True, onerror=onerr, followlinks=True):
        # Resolve current directory real path and mark visited
        try:
            dir_real = os.path.realpath(dirpath)
        except Exception as e:
            errors.append(f"realpath failed for {dirpath}: {e}")
            dir_real = dirpath

        if dir_real in visited_dirs:
            # Already seen this physical directory via a symlink - skip to prevent cycles
            dirnames[:] = []  # prevent descending further
            continue
        visited_dirs.add(dir_real)

        # Prune dirnames that would lead to already-visited targets
        pruned_subfolders = []
        for d in dirnames:
            subdir_path = os.path.join(dirpath, d)
            try:
                subdir_real = os.path.realpath(subdir_path)
            except Exception as e:
                errors.append(f"realpath failed for {subdir_path}: {e}")
                subdir_real = subdir_path
            if subdir_real in visited_dirs:
                # skip this one; avoid loops
                continue
            pruned_subfolders.append(d)
        # mutate dirnames in place for os.walk to respect pruning
        dirnames[:] = pruned_subfolders

        # Sort locally for deterministic output
        subfolders_sorted = sorted(dirnames, key=str.lower)
        files_sorted = sorted(filenames, key=str.lower)

        records.append((dirpath, subfolders_sorted, files_sorted))

    # Tally totals
    total_folders = len(records)
    total_subfolders = sum(len(s) for _, s, _ in records)
    total_files = sum(len(f) for _, _, f in records)

    # Write the output
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("PROJECT INVENTORY (Every folder and file)\n")
        f.write(f"Root: {root_path}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        for dirpath, subfolders, files in sorted(records, key=lambda x: x[0].lower()):
            f.write(f"=== FOLDER: {dirpath} ===\n")

            # Subfolders block
            f.write("-- SUBFOLDERS --\n")
            if subfolders:
                for sf in subfolders:
                    f.write(f"{sf}\n")
            else:
                f.write("(no subfolders)\n")

            # Files block
            f.write("-- FILES --\n")
            if files:
                for name in files:
                    f.write(f"{name}\n")
            else:
                f.write("(no files)\n")

            f.write("\n")

        f.write("=== SUMMARY ===\n")
        f.write(f"Folders (listed):     {total_folders}\n")
        f.write(f"Immediate subfolders: {total_subfolders}\n")
        f.write(f"Files:                {total_files}\n")

        if errors:
            f.write("\n=== ERRORS (non-fatal) ===\n")
            for e in errors:
                f.write(f"{e}\n")

    print(f"Done. Wrote: {out_file}")

if __name__ == '__main__':
    root = r"C:\\Users\\deskt\\Desktop\\Project_SECQ_CLI\\AnswerChain"
    dest = r"C:\\Users\\deskt\\Desktop\\Project_SECQ_CLI\\AnswerChain"
    export_tree_grouped_complete(root, dest)
