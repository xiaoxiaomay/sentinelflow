# scripts/run_rag_with_audit.py
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # <-- repo root

import os, json, time, uuid, argparse, pickle, hashlib
import numpy as np
import faiss
import yaml

from dotenv import load_dotenv
load_dotenv()  # loads .env in repo root by default (if run from repo root)

from sentence_transformers import SentenceTransformer
from openai import OpenAI

from core.audit import HashChainWriter

# import leakage scan core
from scripts.leakage_scan import scan_text


def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_faiss(index_path: str, meta_path: str):
    index = faiss.read_index(index_path)
    with open(meta_path, "rb") as f:
        meta = pickle.load(f)
    return index, meta


def retrieve_topk(model: SentenceTransformer, index, meta_list, query: str, k: int = 5):
    q = model.encode([query], normalize_embeddings=True).astype(np.float32)
    D, I = index.search(q, k)

    hits = []
    for rank, idx in enumerate(I[0].tolist()):
        if idx < 0:
            continue
        # meta_list is list aligned to FAISS positions
        m = meta_list[idx]
        hits.append({
            "rank": rank + 1,
            "score": float(D[0][rank]),
            "doc_id": m.get("_id") or m.get("id") or m.get("doc_id"),
            "title": m.get("title", ""),
            "text": m.get("text", ""),
            "source_type": m.get("source_type", "public"),
            "trust_score": m.get("trust_score", 1.0),
        })
    return hits


def build_prompt(query: str, hits):
    ctx_lines = []
    for h in hits:
        ctx_lines.append(f"[Doc {h['rank']}] (id={h['doc_id']}, trust={h['trust_score']}, source={h['source_type']})")
        ctx_lines.append(h["title"])
        ctx_lines.append(h["text"])
        ctx_lines.append("")

    context = "\n".join(ctx_lines).strip()
    system = (
        "You are a financial research assistant. Answer the user's query using ONLY the provided context. "
        "If the answer is not in the context, say you do not know. Cite Doc numbers."
    )
    user = f"Query: {query}\n\nContext:\n{context}\n\nAnswer:"
    return system, user


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--query", type=str, required=True)
    ap.add_argument("--config", type=str, default="config.yaml")
    args = ap.parse_args()

    cfg = load_config(args.config)

    # env
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    model_name = os.getenv("OPENAI_MODEL", cfg.get("openai", {}).get("model", "gpt-4o-mini")).strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is missing. Put it in .env as OPENAI_API_KEY=...")

    client = OpenAI(api_key=api_key)

    # load embed model once
    embed_model = SentenceTransformer(cfg["embedding"]["model_name"])

    # load public index/meta
    pub_index, pub_meta = load_faiss(cfg["paths"]["public_index"], cfg["paths"]["public_meta"])

    # load secret index/meta
    sec_index, sec_meta = load_faiss(cfg["paths"]["secret_index"], cfg["paths"]["secret_meta"])

    # retrieve
    rag_k = int(cfg["rag"]["top_k"])
    hits = retrieve_topk(embed_model, pub_index, pub_meta, args.query, k=rag_k)

    # prompt
    system_msg, user_msg = build_prompt(args.query, hits)

    # call llm
    t0 = time.time()
    resp = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_msg},
        ],
        temperature=float(cfg["rag"].get("temperature", 0.2)),
    )
    raw_answer = resp.choices[0].message.content
    latency_ms = int((time.time() - t0) * 1000)

    # leakage scan (sentence-level)
    leak_cfg = cfg["leakage"]
    scan = scan_text(
        text=raw_answer,
        model=embed_model,
        secret_index=sec_index,
        secret_meta=sec_meta,
        hard_threshold=float(leak_cfg["hard_threshold"]),
        soft_threshold=float(leak_cfg["soft_threshold"]),
        cascade_k=int(leak_cfg["cascade_k"]),
        action=str(leak_cfg["action"]),
        top_k_secrets=int(leak_cfg.get("top_k_secrets", 1)),
    )
    final_answer = scan["redacted_text"]

    # audit log (hash chain)
    session_id = str(uuid.uuid4())[:8]
    audit_path = cfg["paths"].get("audit_log", "data/audit/audit_log.jsonl")
    writer = HashChainWriter(audit_path)

    event = {
        "ts": time.time(),
        "session_id": session_id,
        "query": args.query,
        "model": model_name,
        "latency_ms": latency_ms,
        "retrieval": {
            "top_k": rag_k,
            "hits": [
                {
                    "rank": h["rank"],
                    "doc_id": h["doc_id"],
                    "score": round(h["score"], 4),
                    "source_type": h["source_type"],
                    "trust_score": h["trust_score"],
                } for h in hits
            ]
        },
        "leakage": scan["summary"],
        # store hashes for privacy; keep full text optional
        "raw_answer_sha256": hashlib.sha256(raw_answer.encode("utf-8")).hexdigest(),
        "final_answer_sha256": hashlib.sha256(final_answer.encode("utf-8")).hexdigest(),
    }
    writer.append(event)

    print("\n=== SentinelFlow RAG + Leakage Firewall (v1) ===")
    print(f"session_id: {session_id}")
    print(f"latency_ms: {latency_ms}")
    print("\n--- FINAL ANSWER (post-firewall) ---\n")
    print(final_answer)
    print("\n--- LEAKAGE SUMMARY ---")
    print(json.dumps(scan["summary"], ensure_ascii=False, indent=2))
    print(f"\nAudit appended -> {audit_path}")


if __name__ == "__main__":
    main()