#!/usr/bin/env python3
import json, sys, argparse, csv, os
ap = argparse.ArgumentParser()
ap.add_argument("--sarif", required=True)
ap.add_argument("--cwe-map", default="")
ap.add_argument("--out", required=True)
a = ap.parse_args()
def load_map(p):
    m={}
    try:
        with open(p, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                m[r.get("cwe_id","").strip()] = r.get("owasp_top10","").strip()
    except FileNotFoundError:
        pass
    return m
if not os.path.exists(a.sarif):
    open(a.out,"w",encoding="utf-8").write("# No SARIF found\n"); sys.exit(0)
cwe=load_map(a.cwe_map)
s=json.load(open(a.sarif,encoding="utf-8"))
runs=s.get("runs",[]); out=["# CodeQL Executive Summary",""]
tot=0
for run in runs:
    res=run.get("results",[]); tot+=len(res)
    for r in res[:200]:
        rid=r.get("ruleId","")
        msg=(r.get("message",{}) or {}).get("text","")
        tags=(r.get("properties",{}) or {}).get("tags",[])
        cwes=[t for t in tags if str(t).upper().startswith("CWE-")]
        mapped=[f"{c}:{cwe.get(c,'')}" for c in cwes]
        out.append(f"- `{rid}` {msg} {' '.join(mapped)}")
out.append(f"\n**Total findings:** {tot}\n")
open(a.out,"w",encoding="utf-8").write("\n".join(out))
