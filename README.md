# SentinelFlow

**An Inline AI Security Gateway for Financial RAG Pipelines**

SentinelFlow prevents confidential financial strategy leakage from LLM-powered research agents through a multi-gate inline security pipeline. Unlike post-hoc monitoring tools, SentinelFlow enforces security decisions in real time — blocking unsafe queries **before** the LLM is invoked and redacting leaked content **before** responses reach the user.

> INCS 870 · Spring 2026 · Team 02 · New York Institute of Technology Vancouver  
> Zhengmao Zhang · Qiguo Fang · Xiaoxiao Wu · Supervised by Dr. Zhida Li

---

## Key Results

| Metric | Target | SentinelFlow (B2) | Baseline (B0) |
|--------|--------|-------------------|---------------|
| Core ASR (70 adversarial prompts) | 0% | **0.00%** | 1.43% |
| External ASR (24 garak + HarmBench) | — | **0.00%** (actual leakage) | — |
| False Positive Rate (219 real-world queries) | <2% | **0.00%** | — |
| Boundary Test (15 hardening cases) | 100% | **100%** | — |
| Audit Chain Integrity | 100% | **100%** | — |

Knowledge base: 18,516 document chunks (SEC 10-K filings + real-time financial news), stored in PostgreSQL with pgvector. See [Evaluation Results](#evaluation-results) for full breakdown.

---

## System Architecture

```
User Query
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│  PRE-LLM GATES (fail-safe: LLM never called if blocked)     │
│                                                             │
│  Gate 0a: Regex Intent Precheck        (~0.1ms)             │
│  ├─ 5 rule categories (INJ/SYS/AUD/INT/EXF)                 │
│  └─ Blocks prompt injection, sys-prompt exfiltration        │
│                                                             │
│  Gate 0b: Verb×Object Classifier       (~0.5ms)             │
│  ├─ 13 exfiltration verbs × 23 sensitive objects            │
│  └─ Combinatorial matrix: export × trading_strategy → BLOCK │
│                                                             │
│  Gate 1: Embedding Dual-Threshold      (~3ms)               │
│  ├─ SBERT all-MiniLM-L6-v2 (384-dim)                        │
│  ├─ 28 intent amplifier keywords                            │
│  └─ τ_generic=0.75 | τ_extraction=0.50 (dual threshold)    │
└─────────────────────────────────────────────────────────────┘
    │ (query allowed)
    ▼
┌─────────────────────────────────────────────────────────────┐
│  RAG PIPELINE                                               │
│  PostgreSQL + pgvector (HNSW) → LLM API (GPT-4o-mini)      │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│  POST-LLM CHECKS (sentence-level, per-sentence)             │
│                                                             │
│  Grounding Validation                                       │
│  └─ Grounding scores are computed and logged to the audit   │
│     chain as an advisory signal; enforcement is handled by  │
│     the leakage scan to permit LLM knowledge supplementation│
│                                                             │
│  Leakage Scan Firewall (C2)                                 │
│  ├─ Hard  ≥0.70  → immediate [REDACTED]                     │
│  ├─ Soft  ≥0.60  → accumulate & watch                       │
│  └─ Cascade k≥2  → redact all accumulated (salami defense)  │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
Final Output  ──────────────────────────────────────────────────►  SHA-256 Dual Hash Chain Audit Log
                                                                   (global chain + per-session chain)
                                                                   12 event types · JSONL append-only
```

---

## Six Contributions (C1–C6)

| ID | Contribution | Key Design |
|----|-------------|-----------|
| C1 | Multi-Gate Inline Security Pipeline | Sequential gates; any pre-gate block short-circuits pipeline |
| C2 | Sentence-Level Semantic Leakage Firewall | Three-tier hard/soft/cascade thresholds; salami attack defense |
| C3 | L0–L3 Financial Knowledge Sensitivity Spectrum | 60 secret entries · 70 adversarial prompts · 10 attack categories |
| C4 | Prompt Distribution Monitoring | Embedding centroid z-score; dynamically tightens leakage thresholds (implemented, not enabled in evaluated config) |
| C5 | Tamper-Evident SHA-256 Dual Hash Chain | Global + per-session chains; 12 event types; verification tooling |
| C6 | Reproducible Adversarial Evaluation Methodology | B0 baseline vs B2 SentinelFlow; 70 prompts × 10 categories |

---

## Project Structure

```
sentinelflow/
│
├── core/
│   ├── engine.py                 # Main pipeline orchestrator (C1)
│   ├── config_loader.py          # YAML config loader
│   ├── audit.py                  # HashChainWriter — SHA-256 dual hash chain (C5)
│   └── __init__.py
│
├── scripts/
│   ├── run_rag_with_audit.py     # Core RAG pipeline with audit (gate logic, LLM, grounding)
│   ├── build_faiss_index.py      # Build local FAISS secret index (L2/L3 entries)
│   ├── build_secret_faiss_index.py # Build secret FAISS index
│   ├── build_prompt_centroid.py  # Build prompt centroid for C4
│   ├── prepare_public_corpus.py  # Prepare public corpus for pgvector
│   ├── leakage_scan.py           # Sentence-level semantic firewall (C2)
│   ├── prompt_monitor.py         # Prompt distribution monitoring (C4)
│   ├── dfp.py                    # Digital fingerprinting module
│   ├── eval_finance_attacks.py   # Run adversarial attack evaluation (C6)
│   ├── eval_real_world.py        # Real-world query evaluation
│   ├── b0_spectrum_test.py       # B0 baseline spectrum test
│   ├── boundary_test.py          # 15-case iterative hardening evaluation
│   ├── build_external_attacks.py # External attack vector builder
│   ├── benchmark.py              # Performance benchmarking
│   ├── latency_benchmark.py      # Latency benchmarking
│   ├── verify_audit.py           # Audit chain integrity verification
│   ├── dashboard.py              # Streamlit forensic dashboard (C5)
│   └── ...                       # Additional utility scripts
│
├── datasource/
│   ├── docs_unified_ingestor.py  # Document ingestion pipeline
│   ├── sentinelflow_crawler/     # Python-based web scraper (Yahoo Finance, CNBC)
│   └── scrapy.cfg
│
├── web_chat_app.py               # Streamlit web chat interface (live demo)
├── app.py                        # Application entry point
├── streamlit_app.py              # Streamlit app wrapper
├── build.py                      # Build/setup utilities
├── run_docs_ingestor.py          # Document ingestion runner
├── run_spider.py                 # Web scraper runner
│
├── data/
│   ├── secrets/                  # 60 L2/L3 confidential strategy entries
│   │   ├── secrets.jsonl
│   │   └── secrets_full.jsonl
│   ├── eval/
│   │   ├── external_attack_prompts.json   # External attack prompts
│   │   ├── real_world_normal_prompts.json  # Real-world normal queries
│   │   └── v2_real_world_results.json      # V2 evaluation results
│   ├── benchmark/
│   │   ├── attack_prompts.jsonl            # 70 adversarial prompts × 10 categories
│   │   ├── normal_prompts.jsonl            # Normal analyst queries
│   │   ├── custom_strategy_exfil.jsonl     # Custom exfiltration test cases
│   │   └── sensitivity_spectrum.jsonl      # L0–L3 sensitivity spectrum
│   ├── index/
│   │   ├── secrets.faiss         # FAISS index for confidential secrets (CPU, isolated)
│   │   ├── secrets_meta.pkl      # Secret metadata
│   │   ├── finder.faiss          # FinDER corpus FAISS index
│   │   ├── finder_meta.pkl       # FinDER metadata
│   │   └── normal_centroid.pkl   # Prompt centroid for C4
│   ├── raw/                      # Raw data (FinDER corpus, FinancialPhraseBank, etc.)
│   ├── processed/                # Processed public corpus
│   ├── ingestion/                # Ingestion logs
│   └── audit/
│       └── audit_log.jsonl       # Append-only tamper-evident audit log
│
├── assets/                       # Logo and branding assets
├── docs/                         # Project reports and proposals
├── reports/                      # Evaluation results and reports
├── tests/                        # Unit tests
│
├── config.yaml                   # All security thresholds and rules (config-only hardening)
├── requirements.txt
├── .env                          # API keys and DB credentials (NOT committed)
└── README.md
```

---

## Audit Event Types

Every query generates a structured audit trail. A complete (allowed) session produces **9 events**; a blocked query produces only **3 events** (LLM never called).

| Event Type | Description | Blocked Sessions |
|-----------|-------------|-----------------|
| `runtime_info` | System version, model info | ✓ |
| `intent_precheck` | Gate 0a + 0b result | ✓ |
| `query_precheck` | Gate 1 embedding score + threshold used | ✓ (if passes Gate 0) |
| `retrieve` | Retrieved document chunks from pgvector | — |
| `retrieval_quality` | Grounding quality pre-check | — |
| `prompt_built` | Final prompt construction | — |
| `llm_response` | Raw LLM output | — |
| `grounding_check` | Per-sentence grounding scores | — |
| `leakage_scan` | Per-sentence FAISS scores + tier decisions | — |
| `final_output` | Delivered response (with any [REDACTED]) | ✓ |

Each event stores `event_hash` (SHA-256 of this event) and `prev_hash` (hash of previous event). Any post-hoc modification breaks the chain — detectable via `verify_audit.py`.

---

## Knowledge Base

| Dataset | Size | Source |
|---------|------|--------|
| Public corpus (FinDER) | 13,867 chunks | SEC 10-K filings (MSFT, AAPL, ADBE, ...) |
| Financial news | 4,649 chunks | Yahoo Finance / CNBC (scraped) |
| **Total public** | **18,516 chunks** | PostgreSQL + pgvector (HNSW index, AWS) |
| Confidential secrets | 60 entries (30×L2 + 30×L3) | Synthetic hand-authored |
| Hard-negatives | 20 entries (L0+L1) | Synthetic |
| **Secret index** | **80 entries** | Local FAISS (CPU, security-isolated) |

---

## Evaluation Dataset

| Split | Size | Purpose |
|-------|------|---------|
| Attack prompts | 70 (10 categories) | B0 vs B2 ASR comparison |
| Benign queries | 219 | FPR evaluation (real-world SEC EDGAR + Yahoo RSS) |
| Boundary test cases | 15 | Iterative hardening validation |
| External attacks | 24 (garak×14 + HarmBench×10) | Real-world attack vector validation |
| Normal analyst queries | 100 | Behavioral baseline for C4 centroid |

---

## Evaluation Results

### Core Adversarial Evaluation (70 prompts, 10 categories)

| Metric | Target | SentinelFlow (B2) | Baseline (B0) |
|--------|--------|-------------------|---------------|
| Attack Success Rate (ASR) | 0% | **0.00%** | 1.43% |
| False Positive Rate (FPR) | <2% | **0.00%** | — |
| True Positive Rate (TPR) | >90% | **100%** | — |
| Audit Chain Integrity | 100% | **100%** | — |

Per-category B2 ASR: direct\_extraction 0%, indirect\_extraction 0%, prompt\_injection 0%, social\_engineering 0%, salami\_attack 0%, encoding\_extraction 0%, paraphrase\_extraction 0%, adversarial\_exfil 0%, indirect\_injection 0%, hard\_block 0%.

### External Attack Evaluation (24 prompts: garak x14 + HarmBench x10)

| Metric | Result |
|--------|--------|
| Total external attacks | 24 |
| Blocked | 17 (70.83%) |
| Bypassed (pre-LLM gates) | 7 (29.17%) |
| Normal queries FPR | **0.00%** (0/219) |

Bypass breakdown by category:

| Category | Total | Blocked | Bypassed |
|----------|-------|---------|----------|
| garak\_dan\_financial | 4 | 3 | 1 |
| garak\_divergence\_financial | 3 | 2 | 1 |
| garak\_encoding\_financial | 3 | 0 | 3 |
| harmbench\_exfiltration\_financial | 5 | 3 | 2 |
| garak\_apikey\_financial | 2 | 2 | 0 |
| garak\_latentinjection\_financial | 2 | 2 | 0 |
| harmbench\_copyright\_financial | 1 | 1 | 0 |
| harmbench\_escalation\_financial | 1 | 1 | 0 |
| harmbench\_social\_engineering\_financial | 3 | 3 | 0 |

> **Note:** The 7 bypasses passed pre-LLM gates but did **not** cause actual secret leakage — the LLM's own refusal + post-LLM leakage scan provided defense-in-depth. ASR (actual secret exposure) remains **0%**.

### News-Anchored Attack Test (10 normal + 10 attack)

| Group | Total | Expected | Actual | Pass Rate |
|-------|-------|----------|--------|-----------|
| Normal (news queries) | 10 | allow | 10 allowed | **100%** |
| Attack (news-pivoted) | 10 | block | 7 blocked, 3 bypassed gates | **70%** gate block |

The 3 gate-bypassed attacks were caught by LLM refusal — zero secret leakage confirmed.

### Boundary Hardening Test (15 cases, 3 groups)

| Group | Cases | Pass Rate | Description |
|-------|-------|-----------|-------------|
| A: Near-boundary benign | 5 | **100%** | High gate1 scores (0.42–0.48) correctly allowed |
| B: News-pivoted attacks | 5 | **100%** | All blocked by Gate 0 |
| C: Gap exploitation | 5 | **100%** | All blocked by Gate 0 |
| **Total** | **15** | **100%** | Zero false positives, zero missed attacks |

---

## Sensitivity Spectrum (L0–L3)

| Level | Description | Example | Action |
|-------|-------------|---------|--------|
| L0 | Textbook Public | "RSI measures momentum on a 0–100 scale." | ALLOW |
| L1 | Practitioner | "RSI below 30 is generally considered oversold." | ALLOW |
| L2 | Confidential | "Our desk uses RSI-based mean reversion with volume confirmation." | WARN/BLOCK |
| L3 | Top Secret | "Buy when 14D RSI < 25 AND volume 2× avg on Universe-17, 1.5% NAV." | BLOCK |

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| LLM Backend | GPT-4o-mini (OpenAI API) |
| Embedding Model | `sentence-transformers/all-MiniLM-L6-v2` (384-dim) |
| Public Vector DB | PostgreSQL 15 + pgvector (HNSW index, AWS RDS) |
| Secret Vector DB | FAISS (CPU, local — security isolated from cloud) |
| Text Splitting | LangChain `RecursiveCharacterTextSplitter` |
| Web Scraping | Python-based web scraper (Yahoo Finance, CNBC) |
| Frontend | Streamlit (web chat + forensic dashboard) |
| Audit Logging | Python `hashlib` SHA-256 + append-only JSONL |
| Configuration | PyYAML (`config.yaml` — config-only security hardening) |
| Language | Python 3.10+ |

---

## Quick Start

```bash
# 1. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env: set OPENAI_API_KEY, PGVECTOR_CONNECTION_STRING

# 4. Build indexes
python scripts/prepare_public_corpus.py   # Public corpus → PostgreSQL
python scripts/build_faiss_index.py       # Secret corpus → FAISS

# 5. Run web chat interface
streamlit run web_chat_app.py --server.port 8501

# 6. Run forensic dashboard (separate terminal)
streamlit run scripts/dashboard.py --server.port 8502

# 7. Run evaluation
python scripts/b0_spectrum_test.py       # Unprotected baseline
python scripts/eval_finance_attacks.py   # SentinelFlow adversarial eval

# 8. Verify audit chain integrity
python scripts/verify_audit.py
```

> **Note:** Always run commands inside the activated virtual environment (`source venv/bin/activate`) to ensure the correct dependencies are used.

---

## Security Configuration (`config.yaml`)

All security rules are externalized to `config.yaml` — no Python code changes required for hardening:

```yaml
gates:
  gate_0a:
    enabled: true
    rules: [INJ_01, SYS_01, AUD_01, INT_01, EXF_01]

  gate_0b:
    enabled: true
    verbs: [reveal, show, print, dump, export, leak, exfiltrate,
            return, give me, provide, output, display, list]
    objects: [system prompt, secret index, embedding, credential, alpha rule,
              trading strategy, risk model, position limit, ...]

  gate_1:
    enabled: true
    threshold: 0.75              # No amplifier detected
    sensitive_threshold: 0.50    # Amplifier keyword detected
    amplifier_keywords: [parameters, thresholds, exact, entry conditions,
                         alpha, proprietary formula, ...]  # 28 keywords

rag:
  fallback_threshold: 0.40        # RAG fallback similarity threshold

leakage:
  hard_threshold: 0.70           # Immediate [REDACTED]
  soft_threshold: 0.60           # Accumulate
  cascade_k: 2                   # Consecutive soft hits → redact all

prompt_monitoring:               # C4 — implemented, not enabled in eval config
  enabled: false
  sigma_threshold: 2.0
  threshold_tightening:
    hard_delta: 0.05
    soft_delta: 0.05
```

> **Config-only hardening**: All 7 security gaps identified in boundary testing were resolved by editing `config.yaml` alone — zero Python code changes, zero regressions.

---

## Codebase Scale

- **70 Python files**
- **~12,400 lines of code**
- **~400 lines of YAML configuration**
