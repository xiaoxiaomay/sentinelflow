# SentinelFlow

**An Inline AI Security Gateway for Financial RAG Pipelines**

SentinelFlow prevents confidential financial strategy leakage from LLM-powered research agents through a multi-gate inline security pipeline. Unlike post-hoc monitoring tools, SentinelFlow enforces security decisions in real time — blocking unsafe queries **before** the LLM is invoked and redacting leaked content **before** responses reach the user.

> INCS 870 · Spring 2026 · Team 02 · New York Institute of Technology Vancouver  
> Zhengmao Zhang · Qiguo Fang · Xiaoxiao Wu · Supervised by Dr. Zhida Li

---

## Key Results

### Thesis Evaluation (70 original prompts)

| Metric | Target | SentinelFlow (B2) | Baseline (B0) |
|--------|--------|-------------------|---------------|
| Core ASR (70 adversarial prompts) | 0% | **0.00%** | 1.43% |
| External ASR (24 garak + HarmBench) | — | **0.00%** (actual leakage) | — |
| False Positive Rate (219 real-world queries) | <2% | **0.00%** | — |
| Boundary Test (15 hardening cases) | 100% | **100%** | — |
| Audit Chain Integrity | 100% | **100%** | — |

### Journal Evaluation (271 expanded prompts, 13 attack categories)

| Metric | Value |
|--------|-------|
| **True end-to-end ASR (full pipeline with LLM)** | **2.58%** (7/271) |
| Pre-gate block rate | 49.1% (133/271 blocked before LLM) |
| False Positive Rate (100 benign queries) | 2.00% |
| McNemar's test (B0 vs B2) | p < 0.001 (significant) |
| End-to-end gate latency (P50) | 28.75 ms |
| Medical domain TPR (config-only adaptation) | 85.00% |
| Medical domain FPR | 0.00% |
| Encoding evasion gate tests | 17/17 passing |

> **Note:** "Pre-gate block rate" measures prompts blocked by regex/embedding gates. "True ASR" measures actual secret leakage through the full pipeline (pre-gates + LLM + leakage scan). Most bypass cases produce no leakage because the LLM does not have access to proprietary secrets.

Knowledge base: 18,516 document chunks (SEC 10-K filings + real-time financial news), stored in PostgreSQL with pgvector. See [Evaluation Results](#evaluation-results) and [RESULTS_SUMMARY.md](RESULTS_SUMMARY.md) for full breakdown.

---

## System Architecture

```
User Query
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│  PRE-LLM GATES (fail-safe: LLM never called if blocked)     │
│                                                             │
│  Gate 0 Decode: Encoding Normalizer    (<0.1ms)             │
│  ├─ Base64, ROT13, Hex, URL, Unicode, Reversed text         │
│  └─ Decodes obfuscated payloads → passes to Gate 0a         │
│                                                             │
│  Gate 0a: Regex Intent Precheck        (~0.1ms)             │
│  ├─ 5 rule categories (INJ/SYS/AUD/INT/EXF)                 │
│  └─ Blocks prompt injection, sys-prompt exfiltration        │
│                                                             │
│  Gate 0b: Verb×Object Classifier       (~0.5ms)             │
│  ├─ 13 exfiltration verbs × 23 sensitive objects            │
│  └─ Combinatorial matrix: export × trading_strategy → BLOCK │
│                                                             │
│  Gate 1: Embedding Dual-Threshold      (~15ms)              │
│  ├─ SBERT all-MiniLM-L6-v2 (384-dim)                        │
│  ├─ 28 intent amplifier keywords                            │
│  ├─ HYP_01: hypothetical/academic framing → τ=0.45          │
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

## Seven Contributions (C1–C7)

| ID | Contribution | Key Design |
|----|-------------|-----------|
| C1 | Multi-Gate Inline Security Pipeline | Sequential gates; any pre-gate block short-circuits pipeline |
| C2 | Sentence-Level Semantic Leakage Firewall | Three-tier hard/soft/cascade thresholds; salami attack defense |
| C3 | L0–L3 Financial Knowledge Sensitivity Spectrum | 60 secret entries · 271 adversarial prompts · 13 attack categories (70 original + 201 paraphrases × 7 evasion techniques) |
| C4 | Prompt Distribution Monitoring | Embedding centroid z-score; dynamically tightens leakage thresholds (implemented, not enabled in evaluated config) |
| C5 | Tamper-Evident SHA-256 Dual Hash Chain | Global + per-session chains; 12 event types; verification tooling |
| C6 | Reproducible Adversarial Evaluation Methodology | Bypass root-cause analysis; ablation across 7 configs; 5-run statistical eval (McNemar p<0.001); per-gate latency benchmark |
| C7 | Cross-Domain Generalization | Medical domain pilot: 85% TPR, 0% FPR — config-only adaptation, zero code changes |

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
│   ├── salami_detector.py        # Session-level salami attack detection
│   ├── embedding_benchmark.py    # Embedding model comparison benchmark
│   ├── latency_benchmark.py      # Latency benchmarking
│   ├── verify_audit.py           # Audit chain integrity verification
│   ├── run_demo.py               # Demo cases for SentinelFlow
│   ├── archive/                  # Archived/superseded utility scripts
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
| Attack prompts (original) | 70 (10 categories) | B0 vs B2 ASR comparison (thesis) |
| Attack prompts (expanded) | 271 (13 categories) | Journal evaluation — 201 adversarial paraphrases × 7 evasion techniques added |
| Benign queries | 219 | FPR evaluation (real-world SEC EDGAR + Yahoo RSS) |
| Boundary test cases | 15 | Iterative hardening validation |
| External attacks | 24 (garak×14 + HarmBench×10) | Real-world attack vector validation |
| Normal analyst queries | 100 | Behavioral baseline for C4 centroid |
| Medical secrets | 20 (10×L2 + 10×L3) | Cross-domain generalization pilot |
| Medical attack prompts | 20 | Medical domain adversarial evaluation |

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
streamlit run app.py --server.port 8502

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

- **70+ Python files**
- **~14,000 lines of code**
- **~500 lines of YAML configuration**

---

## Reproducing Paper Results

### Prerequisites

```bash
pip install -r requirements.txt
# scipy and matplotlib needed for statistical eval and plots:
pip install scipy matplotlib statsmodels
```

### Docker Deployment (Recommended for Reviewers)

The project includes `Dockerfile` and `docker-compose.yml` for fully containerized, reproducible evaluation. **No PostgreSQL needed** — all evaluation scripts run with local FAISS indexes.

**Step 1: Build the image** (~5 min, downloads embedding model):
```bash
docker-compose build
```

**Step 2: Run evaluations** (no API key needed for most):
```bash
# Ablation study — 7 configurations, ~2 min
docker-compose run --rm ablation

# Latency benchmark — per-gate timing + plot, ~3 min
docker-compose run --rm latency

# Medical domain generalization, ~1 min
docker-compose run --rm medical

# Statistical evaluation (5 runs), ~2 min
docker-compose run --rm statistical
```

**Step 3: Full evaluation suite** (requires OPENAI_API_KEY for LLM calls):
```bash
OPENAI_API_KEY=sk-... docker-compose run --rm full-eval
# Runs all evaluations including full pipeline eval with LLM
# Estimated API cost: ~$0.01 (GPT-4o-mini)
```

Results are saved to `eval/results/` (mounted as Docker volume).

**Available Docker services:**

| Service | Profile | API Key? | Description |
|---------|---------|----------|-------------|
| `ablation` | `eval` | No | Ablation study (7 gate configs) |
| `latency` | `latency` | No | Per-gate latency benchmark + PDF plot |
| `medical` | `medical` | No | Medical domain generalization eval |
| `statistical` | `statistical` | No | Multi-run statistical eval (5 runs) |
| `full-eval` | `full` | Yes | All evaluations + full pipeline with LLM |
| `sentinelflow` | (default) | Yes | Streamlit web UI (needs PostgreSQL) |

> **Note:** The web UI (`sentinelflow` service) requires an external PostgreSQL database with the financial corpus. Set `USE_POSTGRES=true` and `DB_HOST`/`DB_PASSWORD` environment variables. All evaluation services run without PostgreSQL.

### Full Evaluation Suite (without Docker)

```bash
OPENAI_API_KEY=your-key ./reproduce_paper_results.sh
```

### Individual Evaluations

```bash
# Ablation study (7 configs, no LLM calls needed)
python eval/run_ablation.py --all

# Statistical evaluation (5 runs, B0 vs B2)
python eval/run_statistical_eval.py --runs 5

# Latency benchmark (per-gate timing + scalability)
python eval/run_latency_benchmark.py

# Medical domain generalization
python eval/run_medical_eval.py

# Generate LaTeX tables for paper
python eval/generate_latex_tables.py --results-dir eval/results/ --output eval/latex_tables/
```

### Encoding Evasion Tests

```bash
python -m pytest tests/test_encoding_gate.py -v
```

### New Files (Journal Upgrade)

```
UPGRADE_PLAN.md                          # Upgrade analysis and plan
RESULTS_SUMMARY.md                       # Comprehensive results with true ASR vs bypass rate
data/attack_prompts_expanded.jsonl       # 271 adversarial prompts (expanded from 70)
data/attack_prompts_extended.jsonl       # 30 cross-category attack prompts
data/medical/                            # Medical domain pilot data
gates/gate_0_decode.py                   # Encoding detection gate (Base64/ROT13/Hex/URL/Unicode)
eval/run_ablation.py                     # Ablation study (7 configurations)
eval/run_statistical_eval.py             # Multi-run statistical evaluation
eval/run_latency_benchmark.py            # Publication-quality latency benchmark
eval/run_medical_eval.py                 # Cross-domain generalization evaluation
eval/run_full_pipeline_eval.py           # Full pipeline eval with LLM (true ASR measurement)
eval/analyze_bypass_cases.py             # Bypass root cause analysis (Phase 11)
eval/generate_latex_tables.py            # LaTeX table generator for paper
eval/ablation_table.py                   # Ablation-specific LaTeX table
eval/results/                            # All evaluation result JSONs
eval/latex_tables/                       # LaTeX table snippets for paper
eval/figures/latency_plot.pdf            # Latency visualization
config_medical.yaml                      # Medical domain configuration
Dockerfile                               # Docker containerization
docker-compose.yml                       # Docker Compose orchestration
reproduce_paper_results.sh               # One-command reproduction script
sentinelflow_journal_v2.tex              # IEEE 2-column journal format (latest)
tests/test_encoding_gate.py              # Encoding gate unit tests
```
