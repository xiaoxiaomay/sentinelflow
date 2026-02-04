# scripts/leakage_scan.py
import pickle
import re
from typing import Any, Dict, List, Optional

import faiss
import numpy as np

_SENT_SPLIT_RE = re.compile(r"(?<=[.!?。！？])\s+")


def split_sentences(text: str) -> List[str]:
    text = (text or "").strip()
    if not text:
        return []
    if len(text) < 3:
        return [text]
    sents = _SENT_SPLIT_RE.split(text)
    return [s.strip() for s in sents if s.strip()]


def load_faiss_index(index_path: str, meta_path: str):
    index = faiss.read_index(index_path)
    with open(meta_path, "rb") as f:
        meta = pickle.load(f)
    return index, meta


def _embed(model, texts: List[str]) -> np.ndarray:
    emb = model.encode(texts, normalize_embeddings=True)
    return np.asarray(emb, dtype="float32")


def _safe_meta_get(meta_obj, idx: int) -> dict:
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


def scan_text(
    text: str,
    model,
    secret_index,
    secret_meta,
    hard_threshold: float = 0.70,
    soft_threshold: float = 0.60,
    cascade_k: int = 2,
    action: str = "redact",            # "redact" or "block"
    top_k_secrets: int = 1,
    return_sentence_table: bool = True,
    # ---- grounding sentence-action (optional) ----
    grounding_enabled: bool = False,
    grounding_threshold: float = 0.55,
    grounding_action: str = "redact",  # currently support "redact" only
    grounding_scores: Optional[List[float]] = None,
    grounding_top_docs: Optional[List[dict]] = None,
) -> Dict[str, Any]:
    """
    Sentence-level firewall:
      - Secret similarity (hard/soft/cascade) -> redact/block
      - Optional grounding sentence-action: if sentence has low grounding_score -> [REDACTED]
    Returns:
      {
        "summary": {...},
        "sentences": [...],
        "redacted_text": "..."
      }
    """
    action = (action or "redact").lower()
    assert action in {"redact", "block"}
    grounding_action = (grounding_action or "redact").lower()

    sents = split_sentences(text)
    if not sents:
        return {
            "summary": {
                "leakage_flag": False,
                "trigger_reason": "none",
                "hard_hits": 0,
                "soft_hits": 0,
                "cascade_triggered": False,
                "grounding_redactions": 0,
                "blocked_sentences": 0,
                "redacted_sentence_indices": [],
                "top_match": None,
            },
            "sentences": [],
            "redacted_text": text or "",
        }

    X = _embed(model, sents)
    D, I = secret_index.search(X, max(1, int(top_k_secrets)))

    sent_rows = []
    hard_hits = 0
    soft_hits = 0
    recent_soft = 0
    cascade_triggered = False

    top_match = None
    top_score = -1e9

    grounding_scores = grounding_scores or []
    grounding_top_docs = grounding_top_docs or []

    for i, sent in enumerate(sents):
        score = float(D[i][0]) if len(D[i]) else -1.0
        idx = int(I[i][0]) if len(I[i]) else -1
        meta = _safe_meta_get(secret_meta, idx) if idx >= 0 else {}

        secret_id = meta.get("secret_id") or meta.get("_id") or meta.get("doc_id") or ""
        title = meta.get("title") or ""
        category = meta.get("category") or meta.get("source_type") or "secret"

        decision = "allow"
        reason = "none"

        if score >= float(hard_threshold):
            hard_hits += 1
            decision = "block" if action == "block" else "redact"
            reason = "hard"
            recent_soft = 0
        elif score >= float(soft_threshold):
            soft_hits += 1
            recent_soft += 1
            if recent_soft >= max(1, int(cascade_k)):
                cascade_triggered = True
                decision = "block" if action == "block" else "redact"
                reason = "cascade_soft"
            else:
                decision = "redact"
                reason = "soft"
        else:
            recent_soft = 0

        # grounding sentence-action
        g_score = float(grounding_scores[i]) if i < len(grounding_scores) else None
        g_doc = grounding_top_docs[i] if i < len(grounding_top_docs) else None

        if grounding_enabled and g_score is not None and g_score < float(grounding_threshold):
            if decision != "block":
                decision = "redact"
            reason = "ungrounded" if reason == "none" else f"{reason}+ungrounded"

        if score > top_score:
            top_score = score
            top_match = {
                "score": round(float(score), 4),
                "secret_id": secret_id,
                "title": title,
                "category": category,
            }

        # IMPORTANT: keep both keys text/sentence for UI compatibility
        sent_rows.append({
            "sent_index": i,
            "text": sent,
            "sentence": sent,
            "score": round(float(score), 4),
            "decision": decision,
            "reason": reason,
            "secret_id": secret_id,
            "title": title,
            "category": category,
            "ground_score": round(float(g_score), 4) if g_score is not None else None,
            "ground_doc": g_doc,
        })

    leakage_flag = (hard_hits > 0) or cascade_triggered
    trigger_reason = "none"
    if hard_hits > 0:
        trigger_reason = "hard"
    elif cascade_triggered:
        trigger_reason = "cascade_soft"
    elif soft_hits > 0:
        trigger_reason = "soft"

    redacted_indices = [r["sent_index"] for r in sent_rows if r["decision"] in {"redact", "block"}]
    grounding_redactions = sum(1 for r in sent_rows if "ungrounded" in (r.get("reason") or ""))
    blocked_sentences = sum(1 for r in sent_rows if (r.get("decision") == "block"))

    if action == "block" and leakage_flag:
        redacted_text = "[BLOCKED] Output blocked by SentinelFlow leakage firewall."
    else:
        out_sents = []
        for r in sent_rows:
            if r["decision"] in {"redact", "block"}:
                out_sents.append("[REDACTED]")
            else:
                out_sents.append(r["text"])
        redacted_text = " ".join(out_sents).strip()
        if not redacted_text or redacted_text.replace("[REDACTED]", "").strip() == "":
            redacted_text = "I do not have enough information."

    summary = {
        "leakage_flag": leakage_flag,
        "trigger_reason": trigger_reason,
        "hard_hits": hard_hits,
        "soft_hits": soft_hits,
        "cascade_triggered": cascade_triggered,
        "grounding_redactions": grounding_redactions,
        "blocked_sentences": blocked_sentences,
        "redacted_sentence_indices": redacted_indices,
        "top_match": top_match,
    }

    return {
        "summary": summary,
        "sentences": sent_rows if return_sentence_table else [],
        "redacted_text": redacted_text,
    }