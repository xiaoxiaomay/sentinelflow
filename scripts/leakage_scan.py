# scripts/leakage_scan.py
import pickle
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import faiss
import numpy as np

# Ensure repo root importable (for dfp import)
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

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
    # ---- DFP integration (optional, default off for backward compat) ----
    dfp_enabled: bool = False,
    dfp_config: Optional[dict] = None,
) -> Dict[str, Any]:
    """
    Sentence-level firewall:
      - Secret similarity (hard/soft/cascade) -> redact/block
      - Optional grounding sentence-action: if sentence has low grounding_score -> [REDACTED]
      - Optional DFP co-occurrence boost: elevates ambiguous cosine scores when
        co-occurrence features confirm leakage pattern
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

    # --- DFP setup ---
    dfp_config = dfp_config or {}
    dfp_boost_val = float(dfp_config.get("dfp_boost", 0.08))
    dfp_cooc_threshold = float(
        (dfp_config.get("cooccurrence") or {}).get("density_threshold", 0.65)
    )
    dfp_weights = dfp_config.get("cooccurrence") or {}
    dfp_entropy_baselines = dfp_config.get("entropy_baselines") or {}
    dfp_w_entropy = float((dfp_config.get("weights") or {}).get("entropy", 0.35))
    dfp_w_cooc = float((dfp_config.get("weights") or {}).get("cooccurrence", 0.65))
    dfp_allowlist = dfp_config.get("financial_allowlist") or []

    # Cluster centroids (optional)
    dfp_strat_centroid = None
    dfp_norm_centroid = None
    dfp_cov_inv = None
    if dfp_enabled:
        cluster_cfg = dfp_config.get("cluster") or {}
        strat_path = cluster_cfg.get("strategy_centroid_path", "")
        norm_path = cluster_cfg.get("normal_centroid_path", "")
        if strat_path and norm_path:
            try:
                from scripts.dfp import load_centroids
                dfp_strat_centroid, dfp_norm_centroid, dfp_cov_inv = load_centroids(
                    strat_path, norm_path
                )
            except Exception:
                pass

    sents = split_sentences(text)
    if not sents:
        empty_summary = {
            "leakage_flag": False,
            "trigger_reason": "none",
            "hard_hits": 0,
            "soft_hits": 0,
            "cascade_triggered": False,
            "grounding_redactions": 0,
            "blocked_sentences": 0,
            "redacted_sentence_indices": [],
            "top_match": None,
        }
        if dfp_enabled:
            empty_summary.update({
                "dfp_entropy_score": 0.0,
                "dfp_cooccurrence_score": 0.0,
                "dfp_composite_score": 0.0,
                "dfp_elevated_count": 0,
                "dfp_cluster_distance": None,
            })
        return {
            "summary": empty_summary,
            "sentences": [],
            "redacted_text": text or "",
        }

    X = _embed(model, sents)
    D, I = secret_index.search(X, max(1, int(top_k_secrets)))

    # --- DFP: compute whole-text scores ---
    dfp_entropy_result = {}
    dfp_cooc_result = {}
    dfp_cluster_result = {}
    per_sentence_cooc_density = []

    if dfp_enabled:
        from scripts.dfp import (
            structural_entropy_score,
            cooccurrence_score,
            strategy_cluster_distance,
            compute_dfp_composite,
        )
        dfp_entropy_result = structural_entropy_score(text, baselines=dfp_entropy_baselines)
        dfp_cooc_result = cooccurrence_score(
            text,
            weights=dfp_weights,
            density_threshold=dfp_cooc_threshold,
            financial_allowlist=dfp_allowlist,
        )
        per_sentence_cooc_density = dfp_cooc_result.get("per_sentence_density", [])

        dfp_cluster_result = strategy_cluster_distance(
            text,
            strategy_centroid=dfp_strat_centroid,
            normal_centroid=dfp_norm_centroid,
            cov_inv=dfp_cov_inv,
        )

    sent_rows = []
    hard_hits = 0
    soft_hits = 0
    recent_soft = 0
    cascade_triggered = False
    dfp_elevated_count = 0

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

        # --- DFP sentence-level boost ---
        sent_cooc_density = per_sentence_cooc_density[i] if i < len(per_sentence_cooc_density) else 0.0
        dfp_elevated = False
        effective_score = score

        if dfp_enabled and score >= soft_threshold and sent_cooc_density > dfp_cooc_threshold:
            from scripts.dfp import compute_dfp_boost
            effective_score, dfp_elevated = compute_dfp_boost(
                cosine_score=score,
                sentence_cooc_density=sent_cooc_density,
                soft_threshold=soft_threshold,
                hard_threshold=hard_threshold,
                dfp_boost=dfp_boost_val,
                cooccurrence_threshold=dfp_cooc_threshold,
            )
            if dfp_elevated:
                dfp_elevated_count += 1

        decision = "allow"
        reason = "none"

        if effective_score >= float(hard_threshold):
            hard_hits += 1
            decision = "block" if action == "block" else "redact"
            reason = "hard" if not dfp_elevated else "hard+dfp_elevated"
            recent_soft = 0
        elif effective_score >= float(soft_threshold):
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
        row = {
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
        }
        if dfp_enabled:
            row["dfp_cooccurrence_density"] = round(sent_cooc_density, 4)
            row["dfp_elevated"] = dfp_elevated
            row["effective_score"] = round(effective_score, 4)
        sent_rows.append(row)

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

    # DFP summary fields
    if dfp_enabled:
        from scripts.dfp import compute_dfp_composite
        summary["dfp_entropy_score"] = dfp_entropy_result.get("entropy_anomaly_score", 0.0)
        summary["dfp_cooccurrence_score"] = dfp_cooc_result.get("cooccurrence_anomaly_score", 0.0)
        summary["dfp_composite_score"] = compute_dfp_composite(
            summary["dfp_entropy_score"],
            summary["dfp_cooccurrence_score"],
            w_entropy=dfp_w_entropy,
            w_cooccurrence=dfp_w_cooc,
        )
        summary["dfp_elevated_count"] = dfp_elevated_count
        summary["dfp_cluster_distance"] = dfp_cluster_result.get("strategy_distance")

    return {
        "summary": summary,
        "sentences": sent_rows if return_sentence_table else [],
        "redacted_text": redacted_text,
    }