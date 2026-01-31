# scripts/leakage_scan.py
import re, pickle, argparse
from typing import List, Dict, Any, Tuple

import numpy as np
import faiss
import yaml
from sentence_transformers import SentenceTransformer


def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def split_sentences(text: str) -> List[str]:
    parts = re.split(r'(?<=[.!?。！？])\s+', text.strip())
    return [p.strip() for p in parts if p.strip()]


def load_faiss_index(index_path: str, meta_path: str):
    index = faiss.read_index(index_path)
    with open(meta_path, "rb") as f:
        meta = pickle.load(f)
    return index, meta


def topk_secret_match(
    model: SentenceTransformer,
    secret_index,
    secret_meta: List[dict],
    sentence: str,
    k: int = 1,
) -> Tuple[float, dict]:
    emb = model.encode([sentence], normalize_embeddings=True).astype(np.float32)
    D, I = secret_index.search(emb, k)  # IP on normalized vectors ~= cosine
    best_i = int(I[0][0])
    best_score = float(D[0][0])
    best_meta = secret_meta[best_i]
    return best_score, best_meta


def scan_text(
    text: str,
    model: SentenceTransformer,
    secret_index,
    secret_meta: List[dict],
    hard_threshold: float,
    soft_threshold: float,
    cascade_k: int,
    action: str,         # "redact" or "block"
    top_k_secrets: int = 1,
) -> Dict[str, Any]:
    sents = split_sentences(text)

    sentences_out = []
    hard_hits = 0
    soft_hits = 0

    # per-sentence scoring
    for i, s in enumerate(sents):
        score, meta = topk_secret_match(
            model, secret_index, secret_meta, s, k=top_k_secrets
        )

        reason = "none"
        decision = "allow"
        triggered_by = "none"

        if score >= hard_threshold:
            reason = "hard_hit"
            decision = action
            triggered_by = "hard"
            hard_hits += 1
        elif score >= soft_threshold:
            reason = "soft_hit"
            decision = "allow"   # cascade later
            triggered_by = "soft"
            soft_hits += 1

        sentences_out.append({
            "sent_index": i,
            "text": s,
            "score": round(score, 4),
            "decision": decision,
            "reason": reason,
            "triggered_by": triggered_by,
            "match": {
                "secret_id": meta.get("_id"),
                "title": meta.get("title"),
                "category": meta.get("category"),
                "score": round(score, 4),
            }
        })

    cascade_triggered = (hard_hits == 0 and soft_hits >= cascade_k)

    # apply cascade redaction (demo-visible)
    redacted_sentence_indices = []
    if cascade_triggered and action == "redact":
        for row in sentences_out:
            if row["reason"] == "soft_hit":
                row["decision"] = "redact"
                row["reason"] = "cascade"
                row["triggered_by"] = "cascade"
                redacted_sentence_indices.append(row["sent_index"])

    # decide leakage_flag + trigger_reason
    if hard_hits > 0:
        leakage_flag = True
        trigger_reason = "hard_hit"
    elif cascade_triggered:
        leakage_flag = True
        trigger_reason = "cascade"
    else:
        leakage_flag = False
        trigger_reason = "none"

    # compute top_match for summary (highest score)
    top_match_row = max(sentences_out, key=lambda r: r["score"]) if sentences_out else None
    top_match = top_match_row["match"] if top_match_row else None

    # produce redacted_text
    if action == "block" and leakage_flag:
        redacted_text = "[BLOCKED] This response was blocked by SentinelFlow leakage policy."
        redacted_sentence_indices = list(range(len(sentences_out)))
    else:
        out = []
        for row in sentences_out:
            if row["decision"] == "redact":
                out.append("[REDACTED]")
                if row["sent_index"] not in redacted_sentence_indices:
                    redacted_sentence_indices.append(row["sent_index"])
            else:
                out.append(row["text"])
        redacted_text = " ".join(out)

    return {
        "version": "leakage_scan_v1",
        "config": {
            "hard_threshold": hard_threshold,
            "soft_threshold": soft_threshold,
            "cascade_k": cascade_k,
            "action": action,
            "top_k_secrets": top_k_secrets,
        },
        "summary": {
            "leakage_flag": leakage_flag,
            "trigger_reason": trigger_reason,
            "hard_hits": hard_hits,
            "soft_hits": soft_hits,
            "cascade_triggered": cascade_triggered,
            "redacted_sentence_indices": sorted(redacted_sentence_indices),
            "top_match": top_match,
        },
        "sentences": sentences_out,
        "redacted_text": redacted_text,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--text", type=str, required=True)
    ap.add_argument("--config", type=str, default="config.yaml")
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()

    cfg = load_config(args.config)
    leak_cfg = cfg["leakage"]
    paths = cfg["paths"]

    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    secret_index, secret_meta = load_faiss_index(paths["secret_index"], paths["secret_meta"])

    result = scan_text(
        text=args.text,
        model=model,
        secret_index=secret_index,
        secret_meta=secret_meta,
        hard_threshold=float(leak_cfg["hard_threshold"]),
        soft_threshold=float(leak_cfg["soft_threshold"]),
        cascade_k=int(leak_cfg["cascade_k"]),
        action=str(leak_cfg["action"]),
        top_k_secrets=int(leak_cfg.get("top_k_secrets", 1)),
    )

    import json
    if args.pretty:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()