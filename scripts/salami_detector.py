"""
scripts/salami_detector.py

Session-Level Salami Attack Detector for SentinelFlow.

Detects multi-turn extraction attempts where individually-benign queries
collectively target a confidential topic across a session window.
"""
import threading
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

import numpy as np


class SalamiSessionTracker:
    """
    Tracks cumulative secret-proximity across a rolling session window.
    Detects 'salami attacks' where individually-benign queries
    collectively target a confidential topic.

    Thread-safe: uses threading.Lock for session dict access.
    """

    def __init__(
        self,
        window_size: int = 10,
        per_query_threshold: float = 0.55,
        session_alert_threshold: float = 0.55,
        min_targeting_queries: int = 3,
        gate1_tightening_delta: float = 0.05,
    ):
        self.window_size = window_size
        self.per_query_threshold = per_query_threshold
        self.session_alert_threshold = session_alert_threshold
        self.min_targeting_queries = min_targeting_queries
        self.gate1_delta = gate1_tightening_delta
        self._sessions: Dict[str, deque] = {}
        self._lock = threading.Lock()

    def track_query(
        self,
        session_id: str,
        query_vec: np.ndarray,
        secret_index,
        secret_meta,
        top_k: int = 5,
    ) -> Dict[str, Any]:
        """
        Record query and check for session-level secret targeting.

        Searches query_vec against secret_index for top_k matches.
        Stores scores per secret_id in the session's rolling window.
        Then calls _compute_cumulative_targeting to check if any secret
        has been cumulatively targeted across multiple queries.

        Returns:
            {
                "session_risk_flag": bool,
                "targeted_secrets": [{"secret_id": str, "avg_score": float, "query_count": int}, ...],
                "cumulative_scores": {secret_id: [scores...]},
                "recommended_gate1_delta": float (0.0 if no risk),
            }
        """
        # Search query against secret index
        qv = query_vec if query_vec.ndim == 2 else query_vec.reshape(1, -1)
        D, I = secret_index.search(qv, max(1, int(top_k)))

        # Build per-secret scores for this query
        query_secret_scores: Dict[str, float] = {}
        for score, idx in zip(D[0].tolist(), I[0].tolist()):
            idx = int(idx)
            if idx < 0:
                continue
            meta = self._safe_meta_get(secret_meta, idx)
            secret_id = (
                meta.get("_id")
                or meta.get("secret_id")
                or meta.get("doc_id")
                or f"idx_{idx}"
            )
            if secret_id not in query_secret_scores or score > query_secret_scores[secret_id]:
                query_secret_scores[secret_id] = float(score)

        # Add to session window (thread-safe)
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = deque(maxlen=self.window_size)
            self._sessions[session_id].append(query_secret_scores)

        # Check cumulative targeting
        risk_flag, targeted_secrets, cumulative_scores = self._compute_cumulative_targeting(session_id)

        return {
            "session_risk_flag": risk_flag,
            "targeted_secrets": targeted_secrets,
            "cumulative_scores": cumulative_scores,
            "recommended_gate1_delta": self.gate1_delta if risk_flag else 0.0,
        }

    def _compute_cumulative_targeting(
        self, session_id: str
    ) -> Tuple[bool, List[dict], Dict[str, List[float]]]:
        """
        For each secret observed in the session window, collect all scores
        above per_query_threshold. If any secret has:
          - min_targeting_queries or more queries with score >= per_query_threshold
          - average score across those queries >= session_alert_threshold
        Then flag as targeted.

        Returns: (risk_flag, targeted_secrets_list, cumulative_scores_dict)
        """
        with self._lock:
            window = list(self._sessions.get(session_id, []))

        if not window:
            return False, [], {}

        # Collect per-secret scores across the window
        secret_scores: Dict[str, List[float]] = {}
        for query_scores in window:
            for secret_id, score in query_scores.items():
                if score >= self.per_query_threshold:
                    if secret_id not in secret_scores:
                        secret_scores[secret_id] = []
                    secret_scores[secret_id].append(score)

        # Check targeting criteria
        targeted = []
        for secret_id, scores in secret_scores.items():
            if len(scores) >= self.min_targeting_queries:
                avg_score = sum(scores) / len(scores)
                if avg_score >= self.session_alert_threshold:
                    targeted.append({
                        "secret_id": secret_id,
                        "avg_score": round(avg_score, 4),
                        "query_count": len(scores),
                    })

        risk_flag = len(targeted) > 0

        # Build cumulative scores dict for audit
        cumulative = {
            sid: [round(s, 4) for s in scores]
            for sid, scores in secret_scores.items()
        }

        return risk_flag, targeted, cumulative

    @staticmethod
    def _safe_meta_get(meta_obj, idx: int) -> dict:
        """Extract metadata for a given index from the secret metadata object."""
        if isinstance(meta_obj, list):
            return meta_obj[idx] if 0 <= idx < len(meta_obj) else {}
        if isinstance(meta_obj, dict):
            ids = meta_obj.get("ids") or []
            titles = meta_obj.get("titles") or []
            texts = meta_obj.get("texts") or []
            row = {}
            if 0 <= idx < len(ids):
                row["_id"] = ids[idx]
            if 0 <= idx < len(titles):
                row["title"] = titles[idx]
            if 0 <= idx < len(texts):
                row["text"] = texts[idx]
            return row
        return {}
