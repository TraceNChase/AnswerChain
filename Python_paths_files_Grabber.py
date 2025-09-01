import os
from datetime import datetime

def export_tree(root_path, dest_path):
    # Timestamp for filename
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out_file = os.path.join(dest_path, f"location of files folders ({timestamp}).txt")

    with open(out_file, "w", encoding="utf-8") as f:
        f.write("PROJECT INVENTORY\n")
        f.write(f"Root: {root_path}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        folder_count = 0
        file_count = 0

        f.write("=== FOLDERS ===\n")
        for dirpath, dirnames, filenames in os.walk(root_path):
            for d in dirnames:
                folder_count += 1
                fullpath = os.path.join(dirpath, d)
                f.write(f"{fullpath}\n")

        f.write("\n=== FILES ===\n")
        for dirpath, dirnames, filenames in os.walk(root_path):
            for fn in filenames:
                file_count += 1
                fullpath = os.path.join(dirpath, fn)
                f.write(f"{fullpath}\n")

        f.write("\n=== SUMMARY ===\n")
        f.write(f"Folders: {folder_count}\n")
        f.write(f"Files:   {file_count}\n")

    print(f"Done. Wrote: {out_file}")

if __name__ == "__main__":
    root = r"C:\Users\deskt\Desktop\Project_SECQ_CLI\SECQ_CLI\SECQ_CLI"
    dest = r"C:\Users\deskt\Desktop\Project_SECQ_CLI\SECQ_CLI"
    export_tree(root, dest)
