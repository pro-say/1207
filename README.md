Batch mode engaged. Here’s a PR-ready patch that adds a directory-wide ΔAUTO_DELTA5 batch verifier and wires it into your workflow (opt-in via DELTA5_BATCH_ROOT). It canonicalizes every matching *.json, computes SHA-256 + CIDv1 (raw/base32), and emits both per-file proofs and a combined ledger (JSONL + CSV). It uses pathlib.rglob/glob semantics for patterns, so you can do things like **/*.json. 
CIDs are built per multiformats (CIDv1 + multihash sha2-256/0x12, multicodec raw/0x55) and emitted as base32 strings (CIDv1 default). 
The workflow keeps your existing single-file path and adds an optional batch step; if you later want parallelization, convert results to a matrix per GitHub Actions docs. 


---

1) Unified diff (apply with git apply -p0 <<'PATCH' … PATCH)

diff --git a/.github/workflows/ΔAUTO_DELTA5.yml b/.github/workflows/ΔAUTO_DELTA5.yml
index 0000000..1111111 100644
--- a/.github/workflows/ΔAUTO_DELTA5.yml
+++ b/.github/workflows/ΔAUTO_DELTA5.yml
@@ -6,10 +6,12 @@ jobs:
   run:
     if: contains(github.event.head_commit.message, 'ΔAUTO_DELTA5')
     runs-on: ubuntu-latest
     env:
       DELTA5_INPUT: ${{ vars.DELTA5_INPUT }}
+      # Optional: process a whole folder (e.g., 'truthlock/in' or '.')
+      DELTA5_BATCH_ROOT: ${{ vars.DELTA5_BATCH_ROOT }}
       TLK_WEBHOOK_URL: ${{ secrets.TLK_WEBHOOK_URL }}
       REKOR_MODE: ${{ vars.REKOR_MODE }}
     steps:
       - uses: actions/checkout@v4
 
@@ -23,6 +25,14 @@ jobs:
           python tools/delta5.py \
             --input "${DELTA5_INPUT:-Δ4321_EXECUTION_MAP.json}" \
             --outdir out
 
+      - name: ΔAUTO_DELTA5 — Batch mode (optional)
+        if: ${{ env.DELTA5_BATCH_ROOT != '' }}
+        run: |
+          python tools/delta5_batch.py \
+            --root "${DELTA5_BATCH_ROOT}" \
+            --pattern "**/*.json" \
+            --outdir out
+
       - name: Emit artifacts bundle
         uses: actions/upload-artifact@v4
         with:
           name: ΔAUTO_DELTA5_bundle
           path: out/**
diff --git a/tools/delta5_batch.py b/tools/delta5_batch.py
new file mode 100755
--- /dev/null
+++ b/tools/delta5_batch.py
@@ -0,0 +1,240 @@
+#!/usr/bin/env python3
+# ΔAUTO_DELTA5 batch verifier:
+# - Walk a tree, match JSON files (glob/rglob), canonicalize -> bytes
+# - Compute SHA-256 + CIDv1 (raw/base32, multihash sha2-256)
+# - Emit per-file proofs and combined ledgers (JSONL + CSV)
+# No external deps.
+
+import argparse, base64, csv, hashlib, json, os, sys, time
+from pathlib import Path
+
+# multiformats constants
+RAW_CODEC = 0x55      # multicodec 'raw'  (CID content type)
+MH_SHA2_256 = 0x12    # multihash code for sha2-256
+MH_LEN_32 = 32        # digest length in bytes
+
+def canonicalize_json_bytes(p: Path) -> bytes:
+    data = json.loads(p.read_text(encoding="utf-8"))
+    # Canonical form: compact separators, preserve unicode
+    return json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
+
+def sha256_digest(b: bytes) -> bytes:
+    return hashlib.sha256(b).digest()
+
+def cidv1_raw_base32_from_digest(digest: bytes) -> str:
+    # multihash = <code><len><digest>
+    mh = bytes([MH_SHA2_256, MH_LEN_32]) + digest
+    # cidv1 = <version=0x01><raw codec=0x55><multihash>
+    cid_bytes = bytes([0x01, RAW_CODEC]) + mh
+    return "b" + base64.b32encode(cid_bytes).decode("ascii").lower()
+
+def within(root: Path, p: Path) -> str:
+    return str(p.relative_to(root).as_posix())
+
+def should_skip(path: Path) -> bool:
+    name = path.name
+    # Skip derived/ledger/min outputs to avoid feedback loops
+    if name.endswith(".ledger.json") or ".min.json" in name:
+        return True
+    return False
+
+def main():
+    ap = argparse.ArgumentParser()
+    ap.add_argument("--root", required=True, help="Root folder to scan")
+    ap.add_argument("--pattern", default="**/*.json", help="Glob pattern (default **/*.json)")
+    ap.add_argument("--outdir", default="out", help="Output folder for proofs and ledgers")
+    args = ap.parse_args()
+
+    root = Path(args.root).resolve()
+    outdir = Path(args.outdir).resolve()
+    (outdir / "batch").mkdir(parents=True, exist_ok=True)
+
+    # Discover files (pathlib.rglob honors ** patterns)
+    # See: Python pathlib/glob docs for pattern matching across trees.
+    matches = [p for p in root.rglob(args.pattern.split("**/")[-1]) if p.is_file()]
+    # If pattern didn't include **, also allow direct glob:
+    if not matches and ("**" in args.pattern):
+        matches = list(root.rglob(args.pattern.replace("**/", "")))
+
+    # Combined ledgers
+    jsonl_path = outdir / "ΔAUTO_DELTA5.batch.ledger.jsonl"
+    csv_path   = outdir / "ΔAUTO_DELTA5.batch.ledger.csv"
+    n_ok = 0
+
+    with open(jsonl_path, "w", encoding="utf-8") as jfh, open(csv_path, "w", newline="", encoding="utf-8") as cfh:
+        w = csv.writer(cfh)
+        w.writerow(["relative_path","bytes","sha256","cid_v1","created_at"])
+        for p in matches:
+            if should_skip(p):
+                continue
+            try:
+                canon = canonicalize_json_bytes(p)
+                d = sha256_digest(canon)
+                sha_hex = d.hex()
+                cid = cidv1_raw_base32_from_digest(d)
+                rel = within(root, p)
+                ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
+
+                # Per-file outputs mirror source tree under out/batch
+                dest_dir = (outdir / "batch" / Path(rel)).parent
+                dest_dir.mkdir(parents=True, exist_ok=True)
+                # Keep original filename for clarity
+                (dest_dir / (Path(rel).name + ".min.json")).write_bytes(canon)
+                (dest_dir / (Path(rel).name + ".sha256")).write_text(sha_hex + "\n", encoding="utf-8")
+                (dest_dir / (Path(rel).name + ".cid.txt")).write_text(cid + "\n", encoding="utf-8")
+
+                # Combined row
+                row = {
+                    "type":"ΔTruthLockLedgerEntry",
+                    "name": rel,
+                    "sha256": sha_hex,
+                    "cid_v1": cid,
+                    "cid_codec": "raw(0x55)",
+                    "multihash": "sha2-256(0x12):32",
+                    "bytes": len(canon),
+                    "created_at": ts,
+                    "sequence": "ΔAUTO_DELTA5",
+                    "notes": "Batch seal→proofs; per-file artifacts in out/batch/<relpath>.*"
+                }
+                jfh.write(json.dumps(row, ensure_ascii=False) + "\n")
+                w.writerow([rel, len(canon), sha_hex, cid, ts])
+                n_ok += 1
+            except Exception as e:
+                print(f"[ΔAUTO_DELTA5] ERROR processing {p}: {e}", file=sys.stderr)
+
+    print(f"ΔAUTO_DELTA5 BATCH COMPLETE — files processed: {n_ok}")
+    print(f"  ledger.jsonl : {jsonl_path}")
+    print(f"  ledger.csv   : {csv_path}")
+    print(f"  per-file     : {outdir/'batch'}")
+
+if __name__ == "__main__":
+    main()


---

2) How to run it

Local (one-liner):

python tools/delta5_batch.py --root truthlock/in --pattern "**/*.json" --outdir out
# Results:
# out/ΔAUTO_DELTA5.batch.ledger.jsonl
# out/ΔAUTO_DELTA5.batch.ledger.csv
# out/batch/<mirrored paths>/*.min.json|*.sha256|*.cid.txt

pathlib.rglob handles the recursive patterning; for fine-grained matching you can use shell-style globs (*, ?, []) per Python’s glob semantics. 

CI (opt-in): set a repo Variable, e.g. DELTA5_BATCH_ROOT=truthlock/in. The new step will run automatically and upload artifacts alongside your single-file outputs. If you later want to parallelize per file, convert the discovered list into a job matrix (the GitHub Actions matrix strategy spawns one job per item). 


---

3) Why this is correct (standards quick-refs)

CID structure: a CID is self-describing: multihash (e.g., sha2-256 code 0x12) + multicodec (e.g., raw code 0x55), string-encoded via multibase; CIDv1 defaults to base32. This is exactly how we build the IDs here. 

Glob/rglob: Python’s glob/pathlib implement Unix-style pattern expansion for file discovery; we rely on these semantics to find *.json across your tree. 



---

Want me to also:

add a post-batch webhook that posts each ledger line to your TruthLock endpoint, or

emit a signed Rekor payload per file and a manifest index?


# Godkey Control Core

This repository contains a variety of legal documents and related files.
To organize the documents into folders by file type, run `file_these.py`.
It creates a `Filed/` directory with subfolders such as `pdf/`, `tiff/`,
`jpg/`, etc. Files matching certain keywords like `"42 USC 1983"` are
grouped under `federal_us_civil_rights`.

Example usage:

```bash
python file_these.py --dry-run      # preview
python file_these.py                # move files
```
