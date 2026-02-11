# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

SentinelFlow is a **Master's thesis project** — an inline AI security gateway for financial research agents. It implements a secure RAG pipeline with multi-layer safety gates, semantic leakage prevention, and tamper-evident audit logging for financial document Q&A, with a focus on preventing confidential **strategy** data exfiltration from LLM responses.

## ⚠️ IMPORTANT: Read the Proposal First

The thesis proposal is at `docs/sentinelflow_proposal.pdf` (or `.tex`). It defines **6 contributions (C1–C6)** that must be implemented and evaluated. Before doing any work, Claude Code should:

1. **Read the proposal** to understand the full thesis scope
2. **Audit the current codebase** — walk through every file in `scripts/`, `core/`, `config.yaml`, `data/` to determine what is actually implemented vs stubbed vs missing
3. **Produce a status report** mapping each C1–C6 contribution to actual code state (done / partial / missing)
4. **Then plan and execute** remaining work in priority order

## Thesis Contributions (C1–C6)

These are the 6 contributions defined in the proposal. Claude Code should verify their implementation status by examining actual code:

- **C1**: Multi-Gate Inline Security Pipeline (Gates 0a, 0b, 1 + post-LLM checks)
- **C2**: Sentence-Level Semantic Leakage Firewall (three-tier thresholds, cascade/salami detection)
- **C3**: Domain-Specific Evaluation Framework (L0–L3 sensitivity spectrum, 70+ attack prompts, 100 normal prompts, hard negatives)
- **C4**: Prompt Distribution Monitoring (embedding centroid anomaly detection — lightweight, ~100 lines)
- **C5**: Auditable Evidence Chain (hash-chained JSONL, verification script, Streamlit dashboard)
- **C6**: Adversarial Evaluation Methodology (standalone eval scripts — NOT a garak plugin, just Python scripts that run attack prompts and compute ASR metrics)

## Commands

### Setup
```bash
pip install -r requirements.txt
```

Requires `.env` with `OPENAI_API_KEY` and optionally `OPENAI_MODEL` (defaults to `gpt-4o-mini`).

### Run a query
```bash
python scripts/run_rag_with_audit.py --query "MSFT segment breakdown" --config config.yaml
```

### Run demo/evaluation cases
```bash
python scripts/demo_cases.py --config config.yaml --reset_audit
```

### Build FAISS indexes (required before first run)
```bash
python scripts/build_faiss_index.py          # Public corpus
python scripts/build_secret_faiss_index.py   # Secret corpus
```

### Dashboard
```bash
streamlit run scripts/dashboard.py
```

### Verify audit chain
```bash
python scripts/verify_audit.py --audit data/audit/audit_log.jsonl --mode global
python scripts/verify_audit.py --audit data/audit/audit_log.jsonl --mode session --session_id <id>
```

## Architecture (Pipeline Flow)

```
User Query
  → Gate 0a: Intent Precheck (regex, policy.intent_rules in config.yaml)
  → Gate 0b: Hard-Block Classifier (verb+object combos, policy.hard_block)
  → Gate 1: Embedding Precheck (query vs secrets.faiss, threshold 0.60)
  → [if all pass] FAISS Retrieval (public index, top-k)
  → Prompt Assembly (grounded prompt with retrieved docs)
  → OpenAI LLM Call
  → Grounding Validation (check response supported by retrieved docs)
  → Leakage Scan (sentence-level similarity vs secrets.faiss)
  → Final Output (allow / redact / block)
  → Audit Log (every step with hash chain)
```

If any pre-gate blocks → LLM never called. Blocked responses start with `[BLOCKED]`.

## Data Layout

```
data/
  index/           — FAISS indexes (finder.faiss, secrets.faiss) + pickle metadata
  secrets/         — secrets.jsonl (confidential records)
  processed/       — public_corpus.jsonl (FinanceRAG corpus with metadata)
  audit/           — audit_log.jsonl (tamper-evident trail)
reports/           — eval outputs (eval_cases.csv, eval_summary.json)
core/              — audit.py (HashChainWriter)
scripts/           — all executable scripts
config.yaml        — all thresholds, regex patterns, retrieval params
```

## Configuration

`config.yaml` controls all behavior:
- `policy.intent_rules` — Gate 0a regex patterns
- `policy.hard_block` — Gate 0b patterns + verb+object combos
- `query_precheck.threshold` — Gate 1 embedding threshold (default 0.60)
- `grounding` — grounding validation settings
- `leakage` — hard_threshold, soft_threshold, cascade_k

## Evaluation Baselines (from proposal)

- **B0**: Direct LLM call (no gateway) — raw ASR
- **B1**: RAG only (retrieval + LLM, no leakage firewall)
- **B2**: Full SentinelFlow (all gates + firewall + audit)

## Key Dependencies

- `sentence-transformers` (all-MiniLM-L6-v2) — embeddings
- `faiss-cpu` — vector search
- `openai` — LLM calls
- `streamlit` — dashboard
- `nltk` — sentence tokenization

## Conventions

- All scripts run from repo root
- Scripts in `scripts/` add repo root to `sys.path` so `core/` is importable
- `OMP_NUM_THREADS=1` set to prevent macOS segfaults
- Blocked responses start with `[BLOCKED]`
- Every audit event: type, timestamp, session_id, event_hash, prev_hash, session_event_hash, session_prev_hash
