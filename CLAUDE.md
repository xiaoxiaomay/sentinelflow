# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SentinelFlow is a Python research prototype demonstrating a secure RAG (Retrieval-Augmented Generation) pipeline with multi-layer safety gates, semantic leakage prevention, and tamper-evident audit logging. It targets financial document Q&A with a focus on preventing confidential data exfiltration from LLM responses.

## Commands

### Setup
```bash
pip install -r requirements.txt
```

Requires a `.env` file with `OPENAI_API_KEY` and optionally `OPENAI_MODEL` (defaults to `gpt-4o-mini`).

### Run a query through the pipeline
```bash
python scripts/run_rag_with_audit.py --query "MSFT segment breakdown" --config config.yaml
```

### Run all 31 demo/evaluation cases
```bash
python scripts/demo_cases.py --config config.yaml
# With --reset_audit to clear the audit log first
```

### Build FAISS indexes (required before first run)
```bash
python scripts/build_faiss_index.py          # Public corpus
python scripts/build_secret_faiss_index.py   # Secret corpus
```

### Launch audit dashboard
```bash
streamlit run scripts/dashboard.py
```

### Verify audit chain integrity
```bash
python scripts/verify_audit.py --audit data/audit/audit_log.jsonl --mode global
python scripts/verify_audit.py --audit data/audit/audit_log.jsonl --mode session --session_id <id>
```

## Architecture

### Multi-Gate Pipeline

All query processing flows through `scripts/run_rag_with_audit.py`, which orchestrates 4 sequential gates before producing an answer:

1. **Gate 0a — Intent Precheck** (`intent_precheck`): Regex pattern matching against `policy.intent_rules` in `config.yaml`. Catches prompt injection, system prompt exfiltration, and restricted data requests.

2. **Gate 0b — Hard-Block Classifier** (`hardblock_precheck`): Rule-based classifier combining direct regex patterns with verb+object combination matching (e.g., "reveal" + "secret"). Defined in `policy.hard_block` config section.

3. **Gate 1 — Query Embedding Precheck** (`embedding_secret_precheck`): Embeds the query and searches the secret FAISS index. Blocks if cosine similarity exceeds `query_precheck.threshold` (default 0.60).

4. **Retrieval + LLM + Postchecks**: If all gates pass, retrieves top-k documents from the public FAISS index, builds a grounded prompt, calls OpenAI, then runs grounding validation and leakage scanning on the response.

If any gate blocks, the LLM is never called. Every gate decision is logged to the audit chain.

### Leakage Scan (Postcheck)

`scripts/leakage_scan.py` performs sentence-level semantic scanning of LLM output against the secret index. Uses a three-tier decision: hard threshold (immediate redact), soft threshold (accumulate), and cascade logic (block if N consecutive soft hits). Grounding scores from validation feed into redaction decisions.

### Audit System

`core/audit.py` implements `HashChainWriter` — an append-only JSONL logger where each event contains a SHA256 hash linking to the previous event (both global chain and per-session chain). Event types: `runtime_info`, `intent_precheck`, `query_precheck`, `retrieve`, `prompt_built`, `llm_response`, `grounding_check`, `leakage_scan`, `final_output`.

### Data Layout

- `data/index/` — Pre-built FAISS indexes (`finder.faiss` for public, `secrets.faiss` for confidential) and their pickle metadata files
- `data/secrets/secrets.jsonl` — 20 confidential records (simulated proprietary trading rules) used for leakage detection
- `data/processed/public_corpus.jsonl` — Public financial documents corpus
- `data/audit/audit_log.jsonl` — Tamper-evident audit trail
- `reports/` — Evaluation outputs (`eval_cases.csv`, `eval_summary.json`)

### Configuration

`config.yaml` controls all gate thresholds, regex patterns, retrieval parameters, and leakage scan behavior. Key sections: `policy` (gates 0a/0b), `query_precheck` (gate 1), `grounding`, `leakage`.

### Key Dependencies

- `sentence-transformers` (all-MiniLM-L6-v2) for embeddings
- `faiss-cpu` for vector search
- `openai` for LLM calls (Responses API)
- `streamlit` for the audit dashboard

## Conventions

- All scripts are run from the repo root (paths in config.yaml are relative to repo root).
- Scripts in `scripts/` add the repo root to `sys.path` so `core/` is importable.
- The system sets `OMP_NUM_THREADS=1` and related env vars at the top of `run_rag_with_audit.py` to prevent segfaults on macOS.
- Blocked responses always start with `[BLOCKED]`.
