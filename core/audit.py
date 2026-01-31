# sentinelflow/core/audit.py
import json
import hashlib
from pathlib import Path
from typing import Any, Dict, Optional


def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class HashChainWriter:
    """
    Append-only JSONL writer with tamper-evident hash chaining.
    Each event stores: event_hash + prev_hash
    """
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.prev_hash = "GENESIS"

        # If file already exists, continue chain from last line.
        if self.path.exists() and self.path.stat().st_size > 0:
            try:
                last = None
                with self.path.open("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            last = json.loads(line)
                if last and isinstance(last, dict) and "event_hash" in last:
                    self.prev_hash = last["event_hash"]
            except Exception:
                # If parsing fails, start a new chain; keep file untouched.
                self.prev_hash = "GENESIS"

    def append(self, event: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(event)
        payload["prev_hash"] = self.prev_hash

        event_hash = sha256_str(canonical_json(payload))
        payload["event_hash"] = event_hash

        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

        self.prev_hash = event_hash
        return payload