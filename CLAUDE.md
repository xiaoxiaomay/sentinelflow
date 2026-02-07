# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SentinelFlow is a professional-grade AI security firewall for financial agents, implementing a secure RAG (Retrieval-Augmented Generation) pipeline with multi-layer safety gates, Digital Fingerprinting (DFP), ML-based guard integration, semantic leakage prevention, and tamper-evident audit logging. It targets financial document Q&A with a focus on preventing confidential strategy exfiltration from LLM responses.

**Core differentiation**: Deep understanding of financial semantics — distinguishing "RSI is a momentum oscillator" (educational, ALLOW) from "Buy when 14D RSI < 25 AND volume 2x 20D avg, size 1.5% NAV" (strategy leak, BLOCK).

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

### Expand secret corpus (39 → 150+ records)
```bash
python scripts/generate_secrets.py --config config.yaml --mode append
python scripts/build_secret_faiss_index.py   # Rebuild index after expansion
```

### Calibrate DFP baselines
```bash
python scripts/calibrate_dfp.py --config config.yaml --sample_size 100
```

### Prepare benchmark datasets
```bash
python scripts/benchmark_data.py --config config.yaml --dataset all
```

### Run benchmarks
```bash
python scripts/benchmark.py --config config.yaml --mode all
python scripts/benchmark.py --config config.yaml --mode attack
python scripts/benchmark.py --config config.yaml --mode benign
python scripts/benchmark.py --config config.yaml --mode leakage
python scripts/benchmark.py --config config.yaml --mode ablation
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

### Multi-Gate Pipeline (v2.0)

All query processing flows through `scripts/run_rag_with_audit.py`:

```
Query
  │
  ├── Gate 0: rule_gate() ────────────── <1ms, sync (merged intent + hard-block)
  │
  ├── Shared query encoding ─────────── encode once, reuse for Gate 1 + Retrieve
  │
  ├── Llama Guard (async) ──────────── starts here, runs in parallel with Gate 1
  │
  ├── Gate 1: embedding_secret_precheck ── uses shared query_vec
  │
  ├── AWAIT guard result ───────────── sync point before LLM call
  │
  ├── Retrieve (top-k) ────────────── uses shared query_vec
  │
  ├── LLM call ─────────────────────── only if all gates pass
  │
  ├── Grounding validation
  │
  ├── Leakage scan + DFP fusion ────── cosine + co-occurrence + entropy + clustering
  │
  └── Audit (with DFP + guard scores)
```

If any gate blocks, the LLM is never called. Every gate decision is logged to the audit chain.

#### Gate 0 — Rule Gate (`rule_gate`)
Merged from the former `intent_precheck` + `hardblock_precheck`. Deterministic regex + verb-object pattern matching. Catches prompt injection, system prompt exfiltration, restricted data requests, and known attack patterns. <1ms.

#### Llama Guard / PromptGuard (`scripts/llm_guard.py`)
ML-based semantic classifier running **async in parallel** with Gate 1. Catches sophisticated rephrased attacks and social engineering that regex misses. Supports three backends: PromptGuard (CPU), Llama Guard 3 8B (GPU), or external API. Fail-closed by default (block on timeout/error). Configured via `guard:` section in `config.yaml`. Disabled by default (`guard.enabled: false`).

#### Gate 1 — Embedding Precheck (`embedding_secret_precheck`)
Embeds the query and searches the secret FAISS index. Blocks if cosine similarity exceeds `query_precheck.threshold` (default 0.60). Uses shared query vector to avoid redundant encoding.

### Digital Fingerprinting (DFP) — `scripts/dfp.py`

DFP adds statistical analysis on top of cosine similarity to catch strategy leakage that evades simple embedding matching:

- **Structural entropy**: Character/word Shannon entropy, numeric density, parameter specificity (leaked strategies use precise numbers; educational text uses round numbers)
- **Co-occurrence scoring**: 5-dimensional feature vector per sentence — threshold operator density, conjunction density, actionable verb presence, time-window specificity, position sizing signals. Individual features alone don't trigger; only the co-occurrence of multiple signals does.
- **Strategy fragment clustering**: Offline centroid computation from secrets vs normal corpus. Runtime Mahalanobis distance to strategy vs normal cluster.
- **Two-tier baseline**: Static financial vocabulary allowlist (50+ terms) + learned corpus baseline computed by `calibrate_dfp.py`.
- **Fusion**: DFP acts as a tiebreaker — it only elevates ambiguous cosine scores (soft→hard) when co-occurrence confirms leakage. Never demotes a hard hit.

Configured via `dfp:` section in `config.yaml`. Disabled by default (`dfp.enabled: false`). When disabled, behavior is identical to v1.0.

### Leakage Scan (Postcheck) — `scripts/leakage_scan.py`

Sentence-level semantic scanning of LLM output against the secret index. Three-tier decision: hard threshold (immediate redact), soft threshold (accumulate), cascade logic (block if N consecutive soft hits). Optionally integrates DFP co-occurrence boost and grounding scores.

### Audit System — `core/audit.py`

`HashChainWriter` — append-only JSONL logger where each event contains a SHA256 hash linking to the previous event (both global chain and per-session chain). Event types: `runtime_info`, `intent_precheck`, `llm_guard`, `query_precheck`, `retrieve`, `prompt_built`, `llm_response`, `grounding_check`, `leakage_scan`, `final_output`.

### Benchmarking Pipeline

- **`scripts/benchmark_data.py`**: Download/prepare benchmark datasets (JailbreakBench, AdvBench, Salesforce prompt-leakage, Financial PhraseBank, custom strategy exfiltration)
- **`scripts/benchmark.py`**: Multi-mode benchmark runner (attack/benign/leakage/ablation/all) with metrics: ASR, FPR, SLPR (Strategy Leakage Prevention Rate), SLE (Security-Latency Efficiency), latency P50/P95/P99
- **`scripts/generate_secrets.py`**: Expand secret corpus from 39 to 150+ records across 9 strategy archetypes with 3 sensitivity levels

### Data Layout

- `data/index/` — FAISS indexes (`finder.faiss` for public, `secrets.faiss` for confidential) and pickle metadata
- `data/index/dfp_strategy_centroid.pkl`, `dfp_normal_centroid.pkl` — DFP cluster centroids (generated by `calibrate_dfp.py`)
- `data/secrets/secrets.jsonl` — Confidential records (proprietary trading rules) for leakage detection
- `data/processed/public_corpus.jsonl` — Public financial documents corpus
- `data/audit/audit_log.jsonl` — Tamper-evident audit trail
- `data/benchmark/` — Cached benchmark datasets (JailbreakBench, AdvBench, Salesforce, FPB, custom exfil)
- `reports/` — Evaluation outputs (`eval_cases.csv`, `eval_summary.json`, `benchmark_summary.json`, `benchmark_report.csv`, `benchmark_ablation.json`)

### Configuration

`config.yaml` controls all gate thresholds, regex patterns, retrieval parameters, and leakage scan behavior. Key sections:
- `policy` — Gates 0a/0b (intent rules, hard-block patterns)
- `query_precheck` — Gate 1 threshold
- `grounding` — Grounding validation parameters
- `leakage` — Leakage scan thresholds (hard, soft, cascade)
- `dfp` — Digital Fingerprinting (entropy baselines, co-occurrence weights, cluster paths, allowlist)
- `guard` — Llama Guard / PromptGuard (backend, timeout, fail mode)
- `benchmark` — Benchmark datasets, garak probes, report directory

### Key Dependencies

- `sentence-transformers` (all-MiniLM-L6-v2) for embeddings
- `faiss-cpu` for vector search
- `openai` for LLM calls (Responses API)
- `streamlit` for the audit dashboard
- `datasets` for benchmark dataset downloading (HuggingFace)
- `transformers` for PromptGuard / Llama Guard backends

## Conventions

- All scripts are run from the repo root (paths in config.yaml are relative to repo root).
- Scripts in `scripts/` add the repo root to `sys.path` so `core/` is importable.
- The system sets `OMP_NUM_THREADS=1` and related env vars at the top of `run_rag_with_audit.py` to prevent segfaults on macOS.
- Blocked responses always start with `[BLOCKED]`.
- DFP and Guard are disabled by default for backward compatibility. Enable via `dfp.enabled: true` and `guard.enabled: true` in `config.yaml`.
- All 31 demo cases must pass regardless of DFP/guard settings (they default off).
