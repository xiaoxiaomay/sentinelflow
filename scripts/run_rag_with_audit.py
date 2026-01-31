# scripts/run_rag_with_audit.py

# --- ensure repo root is importable ---
import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
# --------------------------------------

import os, json, time, uuid, pickle, argparse, re
from typing import Any, Dict, List, Tuple

import numpy as np
import faiss
import yaml
from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv
from openai import OpenAI

from core.audit import HashChainWriter
from scripts.leakage_scan import scan_text, load_faiss_index


def load_config(path="config.yaml"):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _extract_ticker(query: str) -> str | None:
    m = re.search(r"\b([A-Z]{1,5})\b", query.strip())
    if not m:
        return None
    t = m.group(1)
    if t in {"AND", "OR", "THE", "FOR", "WITH"}:
        return None
    return t


def retrieve_topk(model, index, meta: List[dict], query: str, k: int = 5, candidate_k: int = 50):
    q = model.encode([query], normalize_embeddings=True).astype("float32")
    D, I = index.search(q, candidate_k)

    ticker = _extract_ticker(query)
    ticker_lower = ticker.lower() if ticker else None

    hits = []
    for rank, (score, idx) in enumerate(zip(D[0].tolist(), I[0].tolist()), start=1):
        idx = int(idx)
        if idx < 0:
            continue

        m = meta[idx]  # meta is list aligned with FAISS positions

        doc_id = (m.get("_id") or m.get("doc_id") or "").strip()
        title = (m.get("title") or "").strip()
        text = (m.get("text") or "").strip()

        bonus = 0.0
        if ticker:
            if doc_id.startswith(ticker):
                bonus += 0.25
            if ticker in title:
                bonus += 0.15
            if ticker_lower and ticker_lower in text.lower():
                bonus += 0.10
            if ticker == "MSFT" and "microsoft" in text.lower():
                bonus += 0.10

        hits.append({
            "rank": rank,
            "score": float(score),
            "score_rerank": float(score + bonus),
            "doc_id": doc_id,
            "title": title,
            "text": text,
            "source_type": m.get("source_type", "public"),
            "trust_score": float(m.get("trust_score", 1.0)),
        })

    hits.sort(key=lambda x: x["score_rerank"], reverse=True)
    return hits[:k], {"ticker": ticker, "candidate_k": candidate_k}


def build_prompt(query: str, docs, max_chars_per_doc: int = 1200) -> str:
    chunks = []
    for d in docs:
        text = (d.get("text") or "")[:max_chars_per_doc]
        chunks.append(
            f"[Doc {d['rank']} | {d.get('doc_id')} | score={d['score']:.3f}]\n"
            f"Title: {d.get('title','')}\n{text}"
        )

    context = "\n\n".join(chunks)
    return f"""You are a financial research assistant.
Answer the user's question using ONLY the provided documents as evidence.
If the documents do not contain the answer, say you do not have enough information.

User question: {query}

Documents:
{context}
"""


def call_llm(prompt: str, model_name: str) -> str:
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    resp = client.responses.create(model=model_name, input=prompt)

    out_text = ""
    for item in resp.output:
        if item.type == "message":
            for c in item.content:
                if c.type == "output_text":
                    out_text += c.text
    return out_text.strip()


def query_precheck(
    model: SentenceTransformer,
    secret_index,
    secret_meta: List[dict],
    query: str,
    threshold: float,
    top_k: int = 3,
) -> Dict[str, Any]:
    """
    Simple + demo-friendly:
    - embed the whole query as one string
    - if top1 >= threshold => block
    """
    q = model.encode([query], normalize_embeddings=True).astype("float32")
    D, I = secret_index.search(q, top_k)

    matches = []
    for score, idx in zip(D[0].tolist(), I[0].tolist()):
        idx = int(idx)
        if idx < 0:
            continue
        m = secret_meta[idx]
        matches.append({
            "secret_id": m.get("_id"),
            "title": m.get("title"),
            "category": m.get("category"),
            "score": float(score),
        })

    top = matches[0] if matches else None
    blocked = bool(top and top["score"] >= threshold)

    return {
        "blocked": blocked,
        "threshold": float(threshold),
        "top_match": top,
        "matches": matches,
        "reason": "semantic_match" if blocked else "below_threshold",
    }


def main():
    load_dotenv()  # loads .env in repo root

    ap = argparse.ArgumentParser()
    ap.add_argument("--query", required=True, type=str)
    ap.add_argument("--config", default="config.yaml", type=str)
    args = ap.parse_args()

    cfg = load_config(args.config)

    # --- required config blocks ---
    if "embedding" not in cfg:
        raise KeyError("config.yaml missing: embedding.model_name")
    if "paths" not in cfg:
        raise KeyError("config.yaml missing: paths.public_index/public_meta/secret_index/secret_meta")
    if "rag" not in cfg:
        raise KeyError("config.yaml missing: rag.top_k/max_context_chars_per_doc")
    if "leakage" not in cfg:
        raise KeyError("config.yaml missing: leakage.hard_threshold/soft_threshold/cascade_k/action")

    embed_model = SentenceTransformer(cfg["embedding"]["model_name"])

    pub_index, pub_meta = load_faiss_index(cfg["paths"]["public_index"], cfg["paths"]["public_meta"])
    sec_index, sec_meta = load_faiss_index(cfg["paths"]["secret_index"], cfg["paths"]["secret_meta"])

    audit_dir = cfg.get("audit", {}).get("out_dir", "data/audit")
    audit_file = cfg.get("audit", {}).get("file_name", "audit_log.jsonl")
    audit_path = str(Path(audit_dir) / audit_file)
    writer = HashChainWriter(audit_path)

    session_id = str(uuid.uuid4())
    query = args.query

    # 0) query precheck (BEFORE retrieve/LLM)
    qp_cfg = cfg.get("query_precheck", {"enabled": False})
    if qp_cfg.get("enabled", False):
        t0 = time.time()
        qp = query_precheck(
            model=embed_model,
            secret_index=sec_index,
            secret_meta=sec_meta,
            query=query,
            threshold=float(qp_cfg.get("threshold", 0.60)),
            top_k=int(qp_cfg.get("top_k_secrets", 3)),
        )
        t_qp = time.time() - t0

        writer.append("query_precheck", {
            "session_id": session_id,
            "query": query,
            "latency_s": round(t_qp, 4),
            "blocked": qp["blocked"],
            "reason": qp["reason"],
            "threshold": qp["threshold"],
            "top_match": qp["top_match"],
            "matches": qp["matches"],
        })

        if qp["blocked"] and str(qp_cfg.get("action", "block")).lower() == "block":
            final_answer = str(qp_cfg.get("block_message", "[BLOCKED]"))
            writer.append("final_output", {
                "session_id": session_id,
                "final_answer_chars": len(final_answer),
                "leakage_flag": True,
                "trigger_reason": "query_precheck_block",
            })
            print("\n=== FINAL ANSWER (blocked at query precheck) ===\n")
            print(final_answer)
            print("\n=== AUDIT LOG ===")
            print(audit_path)
            return

    # 1) retrieve
    rag_cfg = cfg["rag"]
    t0 = time.time()
    docs, rerank_info = retrieve_topk(
        embed_model, pub_index, pub_meta, query,
        k=int(rag_cfg["top_k"]),
        candidate_k=int(rag_cfg.get("candidate_k", 50)),
    )
    t_retrieve = time.time() - t0

    writer.append("retrieve", {
        "session_id": session_id,
        "query": query,
        "top_k": int(rag_cfg["top_k"]),
        "latency_s": round(t_retrieve, 4),
        "docs": [{k: d[k] for k in ("rank", "score", "score_rerank", "doc_id", "title", "source_type", "trust_score")} for d in docs],
        "rerank_info": rerank_info,
    })

    # 2) prompt
    prompt = build_prompt(
        query, docs, max_chars_per_doc=int(rag_cfg["max_context_chars_per_doc"])
    )
    writer.append("prompt_built", {
        "session_id": session_id,
        "prompt_chars": len(prompt),
    })

    # 3) LLM
    model_name = os.getenv("OPENAI_MODEL") or cfg.get("openai_model") or "gpt-4o-mini"
    t1 = time.time()
    raw_answer = call_llm(prompt, model_name=model_name)
    t_llm = time.time() - t1

    writer.append("llm_response", {
        "session_id": session_id,
        "model": model_name,
        "latency_s": round(t_llm, 4),
        "raw_answer_chars": len(raw_answer),
    })

    # 4) leakage scan (answer)
    leak_cfg = cfg["leakage"]
    leak_result = scan_text(
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

    # write BOTH summary + sentence details for dashboard
    writer.append("leakage_scan", {
        "session_id": session_id,
        "summary": leak_result.get("summary", {}),
        "sentences": leak_result.get("sentences", []),
    })

    # 5) final output
    final_answer = leak_result.get("redacted_text", raw_answer)

    writer.append("final_output", {
        "session_id": session_id,
        "final_answer_chars": len(final_answer),
        "leakage_flag": leak_result.get("summary", {}).get("leakage_flag", False),
        "trigger_reason": leak_result.get("summary", {}).get("trigger_reason", "none"),
    })

    print("\n=== FINAL ANSWER (post-firewall) ===\n")
    print(final_answer)
    print("\n=== AUDIT LOG ===")
    print(audit_path)


if __name__ == "__main__":
    main()