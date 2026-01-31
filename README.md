# SentinelFlow

SentinelFlow is a lightweight research prototype demonstrating a secure Retrieval-Augmented Generation (RAG) pipeline with:

- 🔍 Evidence-based retrieval (FAISS + SentenceTransformers)
- 🛡️ Semantic leakage firewall (hard/soft thresholds + cascade scan)
- 🔗 Tamper-evident audit logging (hash chain)
- 📊 Streamlit dashboard for observability and forensics

The project focuses on **LLM safety**, **data leakage prevention**, and **post-hoc auditability**.

---

## Features

### 1) RAG Pipeline
- SentenceTransformers embeddings (`sentence-transformers/all-MiniLM-L6-v2`)
- FAISS vector search
- Top-k retrieval (optionally ticker-aware reranking)
- Prompt construction grounded in retrieved documents

### 2) Leakage Firewall
- Semantic similarity scan against protected “secret” embeddings
- Hard / soft thresholds with cascade logic
- Action: redact (demo-friendly) or block
- Sentence-level decisions (for dashboard inspection)

### 3) Tamper-Evident Audit Log
Every run appends structured events to:

- `data/audit/audit_log.jsonl`

Typical events include:
- `query_precheck`
- `retrieve`
- `prompt_built`
- `llm_response`
- `leakage_scan`
- `final_output`

Each event links to the previous hash to support tamper-evident validation.

### 4) Streamlit Dashboard
Interactive UI to inspect:
- sessions & timelines
- retrieved evidence
- leakage scan results (summary + sentence-level)
- prompt / model / output stats
- evidence chain validation (global or per-session)

---

## Project Structure

```text
sentinelflow/
├── core/
│   ├── __init__.py
│   └── audit.py                  # HashChainWriter (tamper-evident logging)
├── scripts/
│   ├── build_faiss_index.py       # Build public FAISS index
│   ├── build_secret_faiss_index.py# Build secret FAISS index
│   ├── leakage_scan.py            # Semantic leakage detector
│   ├── run_rag_with_audit.py      # RAG + firewall + audit logging
│   └── dashboard.py               # Streamlit dashboard
├── data/
│   ├── processed/                 # processed corpora (optional)
│   ├── index/                     # FAISS indexes + meta
│   ├── secrets/                   # secret corpus (seed)
│   └── audit/                     # audit logs
├── config.yaml
├── .env                           # local secrets (NOT committed)
└── README.md
