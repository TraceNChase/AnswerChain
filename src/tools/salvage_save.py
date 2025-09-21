--- /dev/null
+++ b/AnswerChain/src/tools/salvage_save.py
@@ -0,0 +1,310 @@
+# SPDX-License-Identifier: MIT
+# Recover "Summary of your manually entered questions" from the latest
+# debug .txt log and persist JSON/TXT artifacts to user_configured_security_questions.
+#
+# Usage (PowerShell 7):
+#   cd C:\Users\deskt\Desktop\Project_SECQ_CLI\AnswerChain\src
+#   python .\tools\salvage_save.py
+#
+from __future__ import annotations
+from pathlib import Path
+import sys, re, time
+import json
+from typing import List, Dict, Any, Tuple
+
+# Ensure we can import project-local utilities if present
+HERE = Path(__file__).resolve().parent
+SRC_ROOT = HERE.parent
+if str(SRC_ROOT) not in sys.path:
+    sys.path.insert(0, str(SRC_ROOT))
+
+try:
+    from utils.persistence import ensure_dir, atomic_write_json, atomic_write_text
+except Exception:
+    # Fallback: embed minimal atomic writers if utils is unavailable
+    import os, tempfile, io
+    def ensure_dir(d: Path) -> None:
+        d.mkdir(parents=True, exist_ok=True)
+    def _atomic_replace(tmp: Path, final: Path) -> None:
+        os.replace(str(tmp), str(final))
+    def atomic_write_text(p: Path, s: str) -> None:
+        ensure_dir(p.parent)
+        with tempfile.NamedTemporaryFile(dir=str(p.parent), delete=False) as tf:
+            tmp = Path(tf.name)
+            with io.BufferedWriter(tf) as buf:
+                buf.write(s.encode("utf-8"))
+                buf.flush()
+                os.fsync(tf.fileno())
+        _atomic_replace(tmp, p)
+    def atomic_write_json(p: Path, obj: Any) -> None:
+        atomic_write_text(p, json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
+
+
+LOGS_DIR = SRC_ROOT / "logs" / "debug_logs"
+OUT_DIR  = SRC_ROOT / "user_configured_security_questions"
+
+Q_HEADER = re.compile(r"^\[Question\s+(\d+)\]\s*(.+?)\s*$")
+ALT_LINE = re.compile(r"^\s*([A-Z])\)\s*(.+?)\s*$")
+TYPE_LINE = re.compile(r"^\s*Type:\s*(CRITICAL|STANDARD)\s*$")
+CORRECT_LINE = re.compile(r"^\s*Correct:\s*(.+?)\s*$")
+
+def _latest_txt_log() -> Path:
+    if not LOGS_DIR.exists():
+        raise FileNotFoundError(f"Logs directory not found: {LOGS_DIR}")
+    candidates = sorted(LOGS_DIR.glob("*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
+    if not candidates:
+        raise FileNotFoundError(f"No .txt logs found in: {LOGS_DIR}")
+    return candidates[0]
+
+def _normalize(s: str) -> str:
+    return " ".join(s.strip().split())
+
+def parse_summary_block(lines: List[str]) -> Tuple[List[Dict[str, Any]], str]:
+    """
+    Parse the 'Summary of your manually entered questions:' block.
+    Returns (questions, pretty_block_text)
+    """
+    in_block = False
+    block_lines: List[str] = []
+    questions: List[Dict[str, Any]] = []
+    i = 0
+    while i < len(lines):
+        line = lines[i]
+        if not in_block and "Summary of your manually entered questions:" in line:
+            in_block = True
+            block_lines.append(line.rstrip())
+            i += 1
+            continue
+        if in_block:
+            # End conditions: empty line then non-indented block or new section prompt
+            block_lines.append(line.rstrip())
+            m = Q_HEADER.match(line)
+            if m:
+                # Start a question record
+                q_text = m.group(2).strip()
+                q_alts: List[str] = []
+                q_type = "STANDARD"
+                q_correct_texts: List[str] = []
+                # Scan following lines
+                j = i + 1
+                while j < len(lines):
+                    ln = lines[j].rstrip("\n")
+                    if Q_HEADER.match(ln):
+                        break
+                    block_lines.append(ln)
+                    am = ALT_LINE.match(ln)
+                    if am:
+                        q_alts.append(_normalize(am.group(2)))
+                    tm = TYPE_LINE.match(ln)
+                    if tm:
+                        q_type = tm.group(1).strip()
+                    cm = CORRECT_LINE.match(ln)
+                    if cm:
+                        q_correct_texts = [_normalize(x) for x in cm.group(1).split(",")]
+                    j += 1
+                # Map correct texts to indices
+                corr_idx: List[int] = []
+                for ct in q_correct_texts:
+                    # match against alternatives
+                    matched = False
+                    for idx, alt in enumerate(q_alts):
+                        if ct == alt:
+                            corr_idx.append(idx)
+                            matched = True
+                            break
+                    if not matched and ct:
+                        # Try loose containment
+                        for idx, alt in enumerate(q_alts):
+                            if ct in alt and idx not in corr_idx:
+                                corr_idx.append(idx)
+                                matched = True
+                                break
+                questions.append({
+                    "text": q_text,
+                    "alternatives": q_alts,
+                    "correct_indices": sorted(set(corr_idx)),
+                    "type": q_type,
+                })
+                i = j
+                continue
+            # Terminate when we hit another major section or EOF
+        i += 1
+
+    if not questions:
+        raise ValueError("Could not locate or parse the summary block; verify the log format.")
+    return questions, "\n".join(block_lines).rstrip() + "\n"
+
+def persist_artifacts(questions: List[Dict[str, Any]], pretty_block: str) -> Path:
+    ts = time.strftime("%Y%m%d_%H%M%S")
+    ensure_dir(OUT_DIR)
+    json_path = OUT_DIR / f"user_questions_{ts}.json"
+    txt_path  = OUT_DIR / f"user_questions_{ts}.txt"
+    atomic_write_json(json_path, {
+        "created_at": ts,
+        "questions": questions,
+        "schema_version": 1,
+    })
+    atomic_write_text(txt_path, pretty_block)
+    return json_path
+
+def main() -> int:
+    log = _latest_txt_log()
+    content = log.read_text(encoding="utf-8", errors="replace").splitlines()
+    questions, pretty = parse_summary_block(content)
+    out = persist_artifacts(questions, pretty)
+    print("[OK] Recovered and saved questions.")
+    print(f"JSON: {out}")
+    print(f"TXT : {out.with_suffix('.txt')}")
+    return 0
+
+if __name__ == "__main__":
+    raise SystemExit(main())
