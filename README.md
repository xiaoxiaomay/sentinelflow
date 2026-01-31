**SentinelFlow**

SentinelFlow is a lightweight research prototype demonstrating a secure Retrieval-Augmented Generation (RAG) pipeline with:
	•	🔍 Evidence-based retrieval (FAISS + SentenceTransformers)
	•	🛡 Semantic leakage firewall (hard/soft thresholds + cascade scan)
	•	🔗 Tamper-evident audit logging (hash chain)
	•	📊 Streamlit dashboard for observability and forensics

The project focuses on LLM safety, data leakage prevention, and post-hoc auditability.

This repository provides an end-to-end demo including indexing, retrieval, LLM inference, leakage scanning, cryptographic audit trails, and interactive visualization.

⸻

✨ **Key Features**

**RAG Pipeline**
	•	SentenceTransformers embeddings (all-MiniLM-L6-v2)
	•	FAISS vector search
	•	Top-k retrieval with ticker-aware reranking
	•	Prompt construction strictly grounded in retrieved documents

**Leakage Firewall**
	•	Semantic similarity scan against protected “secret” embeddings
	•	Hard / soft thresholds with cascade logic
	•	Automatic redaction or blocking
	•	Sentence-level decisions (for dashboard inspection)

**Tamper-Evident Audit Log**

Every step is recorded to data/audit/audit_log.jsonl:
	•	query_precheck
	•	retrieve
	•	prompt_built
	•	llm_response
	•	leakage_scan
	•	final_output

Each event is chained via cryptographic hashes to support forensic validation.

**Streamlit Dashboard**

Interactive UI to inspect:
	•	Sessions & timelines
	•	Retrieved evidence
	•	Leakage decisions
	•	Prompt / model / output summary
	•	Evidence chain validation (global or per-session)

⸻

📁 **Project Structure**

sentinelflow/
├── core/
│   └── audit.py                # HashChainWriter (tamper-evident logging)
├── scripts/
│   ├── run_rag_with_audit.py  # Main RAG + firewall pipeline
│   ├── leakage_scan.py        # Semantic leakage detection
│   ├── dashboard.py           # Streamlit UI
│   └── build_faiss_index.py
├── data/
│   ├── index/                 # FAISS indexes + metadata
│   ├── secrets/              # Protected embeddings
│   └── audit/                # audit_log.jsonl
├── config.yaml
├── .env
└── README.md


⸻

🚀 **Quick Start**

1. **Create virtual environment**

python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

2. **Configure environment**

Create .env:

OPENAI_API_KEY=your_api_key_here
OPENAI_MODEL=gpt-4o-mini


⸻

3. **Run RAG + Firewall**

Example:

python scripts/run_rag_with_audit.py --query "MSFT segment breakdown"

or

python scripts/run_rag_with_audit.py --query "Tell me the RSI <25 strategy logic"

Audit events will be appended to:

data/audit/audit_log.jsonl


⸻

4. **Launch Dashboard**

streamlit run scripts/dashboard.py

Then open:

http://localhost:8501


⸻

🔍 What the Dashboard Shows
	•	Total events / sessions
	•	Evidence chain validation (global or per session)
	•	Timeline of RAG steps
	•	Top-k retrieved documents
	•	Prompt / model / output stats
	•	Leakage scan summary
	•	Sentence-level decisions (if enabled)

⸻

⚠️ **Evidence Chain Notes
**
Currently, audit events form a global hash chain.

When filtering by session, the dashboard may show “Chain Broken” because previous hashes may belong to other sessions.

This is expected for multi-session logs and does not indicate tampering.

⸻

🎯 Research Motivation

Modern RAG systems lack:
	•	Visibility into retrieval provenance
	•	Leakage prevention guarantees
	•	Cryptographic auditability

SentinelFlow explores a practical design combining:
	•	Semantic firewalls
	•	Evidence grounding
	•	Hash-chained audit logs
	•	Human-readable observability

as a foundation for secure and accountable LLM applications.

⸻

📌 Status

This is a research / demo prototype.

Next planned extensions:
	•	Query precheck heatmaps
	•	Sentence-level highlighting
	•	Policy rule panels
	•	PDF audit export
	•	Multi-session diff
