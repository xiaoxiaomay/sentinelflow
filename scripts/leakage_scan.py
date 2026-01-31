# scripts/leakage_scan.py
import re, json, pickle, argparse
from typing import List, Dict, Any, Tuple

import numpy as np
import faiss
import yaml
from sentence_transformers import SentenceTransformer


VERSION = "leakage_scan_v1"


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
    D, I = secret_index.search(emb, k)  # inner product on normalized vectors ~= cosine
    best_i = int(I[0][0])
    best_score = float(D[0][0])
    best_meta = secret_meta[best_i]
    return best_score, best_meta


def redact_sentence(_: str) -> str:
    return "[REDACTED]"


def scan_text(
    text: str,
    model: SentenceTransformer,
    secret_index,
    secret_meta: List[dict],
    hard_threshold: float,
    soft_threshold: float,
    cascade_k: int,
    action: str,
    top_k_secrets: int = 1,
) -> Dict[str, Any]:

    sents = split_sentences(text)
    sentences_out = []

    hard_hits = 0
    soft_hits = 0

    # keep best overall match for summary
    best_overall = {"secret_id": None, "title": None, "category": None, "score": -1.0}

    for i, s in enumerate(sents):
        score, meta = topk_secret_match(
            model, secret_index, secret_meta, s, k=top_k_secrets
        )

        m = {
            "secret_id": meta.get("_id"),
            "title": meta.get("title"),
            "category": meta.get("category"),
            "score": round(score, 4),
        }

        if score > best_overall["score"]:
            best_overall = dict(m)

        decision = "allow"
        reason = "none"

        if score >= hard_threshold:
            decision = action  # redact or block
            reason = "hard_hit"
            hard_hits += 1
        elif score >= soft_threshold:
            decision = "allow"  # decide later by cascade
            reason = "soft_hit"
            soft_hits += 1

        sentences_out.append(
            {
                "sent_index": i,
                "text": s,
                "score": round(score, 4),
                "decision": decision,
                "reason": reason,
                "match": m,
            }
        )

    cascade_triggered = (hard_hits == 0) and (soft_hits >= cascade_k)

    # finalize decisions (cascade turns soft_hit into redact/block)
    redacted_sentence_indices = []

    if action == "block" and (hard_hits > 0 or cascade_triggered):
        redacted_text = "[BLOCKED] Response blocked by SentinelFlow leakage policy."
        trigger_reason = "hard_hit" if hard_hits > 0 else "cascade"
        leakage_flag = True

        # for dashboard: mark which sentences would have been blocked
        for row in sentences_out:
            if row["reason"] in ("hard_hit", "soft_hit"):
                redacted_sentence_indices.append(row["sent_index"])
                row["decision"] = "block"
                if row["reason"] == "soft_hit" and cascade_triggered:
                    row["reason"] = "cascade"

        return {
            "version": VERSION,
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
                "redacted_sentence_indices": redacted_sentence_indices,
                "top_match": best_overall,
            },
            "sentences": sentences_out,
            "redacted_text": redacted_text,
        }

    # redact mode (demo-friendly)
    out_sents = []
    for row in sentences_out:
        if row["reason"] == "hard_hit":
            row["decision"] = "redact"
            out_sents.append(redact_sentence(row["text"]))
            redacted_sentence_indices.append(row["sent_index"])
        elif cascade_triggered and row["reason"] == "soft_hit":
            row["decision"] = "redact"
            row["reason"] = "cascade"
            out_sents.append(redact_sentence(row["text"]))
            redacted_sentence_indices.append(row["sent_index"])
        else:
            out_sents.append(row["text"])

    redacted_text = " ".join(out_sents)

    leakage_flag = (hard_hits > 0) or cascade_triggered
    trigger_reason = "hard_hit" if hard_hits > 0 else ("cascade" if cascade_triggered else "none")

    return {
        "version": VERSION,
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
            "redacted_sentence_indices": redacted_sentence_indices,
            "top_match": best_overall,
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

    model = SentenceTransformer(cfg["embedding"]["model_name"])

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

    if args.pretty:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()