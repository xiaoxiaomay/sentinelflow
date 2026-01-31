# core/audit.py
import os, json, hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional

def _utc_ts() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

class HashChainWriter:
    """
    Append-only tamper-evident audit log.

    Writes BOTH:
      - prev_hash: global chain link (across entire file)
      - session_prev_hash: per-session chain link (safe under session filtering)
    """
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._global_prev = "0" * 64
        self._session_prev: Dict[str, str] = {}  # session_id -> prev hash
        # If file exists, load last global hash and last session hashes (best-effort)
        if os.path.exists(path) and os.path.getsize(path) > 0:
            try:
                self._replay()
            except Exception:
                # If replay fails, keep default; dashboard will show broken for older part
                pass

    def _replay(self):
        """Reconstruct last hashes from existing file (best-effort)."""
        last_global = "0" * 64
        last_session: Dict[str, str] = {}
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                evt = json.loads(line)
                h = evt.get("event_hash")
                if isinstance(h, str) and len(h) == 64:
                    last_global = h
                    sid = (evt.get("body") or {}).get("session_id")
                    if sid:
                        last_session[sid] = h
        self._global_prev = last_global
        self._session_prev = last_session

    def append(self, event_type: str, body: Dict[str, Any], ts: Optional[str] = None) -> Dict[str, Any]:
        ts = ts or _utc_ts()
        session_id = (body or {}).get("session_id", None)

        session_prev = self._session_prev.get(session_id, "0" * 64) if session_id else "0" * 64

        record = {
            "ts": ts,
            "type": event_type,
            "body": body,
            # both chains:
            "prev_hash": self._global_prev,
            "session_prev_hash": session_prev,
        }

        record["event_hash"] = sha256_str(canonical_json(record))

        # append
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(canonical_json(record) + "\n")

        # update pointers
        self._global_prev = record["event_hash"]
        if session_id:
            self._session_prev[session_id] = record["event_hash"]

        return record