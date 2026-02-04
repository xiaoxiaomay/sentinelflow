#!/usr/bin/env python3
# scripts/verify_audit.py
"""
CLI verifier for audit hash chain.
It validates both:
  - global chain (prev_hash links across entire file)
  - per-session chain (prev_hash links within a session sequence)

Usage:
  python scripts/verify_audit.py
  python scripts/verify_audit.py --audit data/audit/audit_log.jsonl
  python scripts/verify_audit.py --mode global
  python scripts/verify_audit.py --mode session --session_id <uuid>
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows = []
    if not path.exists():
        return rows
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                rows.append({"_parse_error": True, "_line_no": i, "_raw": line})
    return rows


def group_by_session(rows: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        body = r.get("body") or {}
        sid = body.get("session_id")
        if not sid:
            continue
        out.setdefault(str(sid), []).append(r)
    return out


def validate_global(rows: List[Dict[str, Any]]) -> Tuple[bool, Optional[int], str]:
    """
    Very lightweight validation:
      - check each row has event_hash and prev_hash
      - verify prev_hash equals previous event_hash in file order
    Note: If your writer uses different keys, update here.
    """
    prev = None
    for idx, r in enumerate(rows):
        if r.get("_parse_error"):
            return False, idx, f"parse error at line {r.get('_line_no')}"
        eh = r.get("event_hash") or r.get("hash") or r.get("event_hash_hex")
        ph = r.get("prev_hash") or r.get("prev") or r.get("prev_hash_hex")
        if eh is None or ph is None:
            return False, idx, f"missing hash fields at index {idx} (need event_hash + prev_hash)"
        if prev is None:
            # first row: prev_hash can be all zeros or empty; we don't enforce exact value
            prev = eh
            continue
        if ph != prev:
            return False, idx, f"prev_hash mismatch at index {idx}: expected {prev}, got {ph}"
        prev = eh
    return True, None, "ok"


def validate_session(rows: List[Dict[str, Any]], session_id: str) -> Tuple[bool, Optional[int], str]:
    srows = [r for r in rows if (r.get("body") or {}).get("session_id") == session_id]
    if not srows:
        return False, None, f"no rows found for session_id={session_id}"

    prev = None
    for idx, r in enumerate(srows):
        eh = r.get("event_hash") or r.get("hash") or r.get("event_hash_hex")
        ph = r.get("prev_hash") or r.get("prev") or r.get("prev_hash_hex")
        if eh is None or ph is None:
            return False, idx, f"missing hash fields in session at step {idx}"
        if prev is None:
            prev = eh
            continue
        if ph != prev:
            return False, idx, f"session prev_hash mismatch at step {idx}: expected {prev}, got {ph}"
        prev = eh

    return True, None, "ok"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", default="data/audit/audit_log.jsonl", type=str)
    ap.add_argument("--mode", default="global", choices=["global", "session"])
    ap.add_argument("--session_id", default="", type=str)
    args = ap.parse_args()

    audit_path = Path(args.audit)
    rows = load_jsonl(audit_path)
    print(f"Audit: {audit_path}  rows={len(rows)}")

    if args.mode == "global":
        ok, idx, msg = validate_global(rows)
        print(f"GLOBAL: {'OK' if ok else 'BROKEN'}  {msg}")
        if not ok and idx is not None:
            print("Broken row (approx):")
            print(json.dumps(rows[idx], ensure_ascii=False, indent=2)[:2000])
        return

    # session mode
    if not args.session_id:
        # list sessions
        sessions = group_by_session(rows)
        print(f"Sessions: {len(sessions)}")
        for sid, srows in list(sessions.items())[:20]:
            print(f"  {sid}  events={len(srows)}")
        print("\nTip: rerun with --session_id <uuid>")
        return

    ok, idx, msg = validate_session(rows, args.session_id)
    print(f"SESSION({args.session_id}): {'OK' if ok else 'BROKEN'}  {msg}")
    if not ok and idx is not None:
        # show around mismatch
        srows = [r for r in rows if (r.get("body") or {}).get("session_id") == args.session_id]
        lo = max(0, idx - 2)
        hi = min(len(srows), idx + 3)
        print("\nContext rows:")
        for j in range(lo, hi):
            print(f"\n--- step {j} ---")
            print(json.dumps(srows[j], ensure_ascii=False, indent=2)[:2000])


if __name__ == "__main__":
    main()