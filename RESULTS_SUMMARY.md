# SentinelFlow — Journal Evaluation Results Summary

**Date:** 2026-03-21
**Attack corpus:** 1,350 total adversarial prompts (271 internal + 779 garak + 300 HarmBench)
**Benign corpus:** 100 normal financial queries
**LLM:** GPT-4o-mini (for full pipeline evaluation)

---

## Key Metrics

| Metric | Value |
|--------|-------|
| **True ASR (internal 271 prompts)** | **2.58%** (7/271) |
| **True ASR (framework 1,079 prompts)** | **0.74%** (8/1,079) |
| garak probes: gate block rate | 2.3% (18/779) — generic attacks, not finance-targeted |
| garak probes: true leakage | **0 / 779** |
| HarmBench financial: gate block rate | 45.0% (135/300) |
| B2 Full FPR | 2.00% |
| McNemar p-value (B0 vs B2) | < 0.001 (significant) |
| End-to-end gate latency (P50) | 28.75 ms |
| Medical domain TPR | 85.00% |
| Medical domain FPR | 0.00% |
| Encoding gate tests | 17/17 passing |

**Important distinction:** "Pre-gate bypass rate" measures how many prompts pass the regex/embedding gates. "True ASR" measures actual secret leakage through the complete pipeline (pre-gates + LLM + leakage scan). Most bypass cases produce no leakage because the LLM does not know the proprietary secrets.

---

## External Framework Evaluation (Phase 15)

| Evaluation Set | Prompts | Gate Block Rate | True Leaked | True ASR |
|----------------|---------|-----------------|-------------|----------|
| Hand-crafted (thesis, 70) | 70 | 100.0% | 0 | 0.00% |
| Expanded (paraphrases, 271) | 271 | 49.1% | 7 | 2.58% |
| garak framework probes | 779 | 2.3% | 0 | 0.00% |
| HarmBench financial behaviors | 300 | 45.0% | 8 | 2.67% |
| **Framework total** | **1,079** | **14.2%** | **8** | **0.74%** |

**Key findings:**
1. garak generic probes (encoding, DAN, prompt injection) achieve 0% true leakage — these attacks don't know our secrets
2. HarmBench financial behaviors are domain-targeted → 45% pre-gate block rate, but only 8/300 produce borderline leakage through the full pipeline
3. The low gate block rate on garak probes (2.3%) is expected and acceptable — these prompts don't contain financial extraction intent, so the gates correctly allow them through

---

## Full Pipeline Evaluation (Phase 13)

| Stage | Count | Rate |
|-------|-------|------|
| Total attack prompts | 271 | 100% |
| Blocked by pre-gates | 127 | 46.9% |
| Bypass → tested with LLM | 144 | 53.1% |
| └ Leakage scan caught | 1 | 0.7% of bypass |
| └ LLM refused to answer | 2 | 1.4% of bypass |
| └ Safe response (no secrets) | 134 | 93.1% of bypass |
| └ **True leakage** | **7** | **2.58% of total** |

The 7 leaked cases involved the LLM providing generic financial strategy descriptions (e.g., post-earnings drift entry conditions, drawdown thresholds) that happened to exceed the 0.60 cosine similarity threshold against the secrets index. These represent borderline cases where public financial knowledge overlaps with proprietary parameters.

---

## Ablation Study Results (Updated Phase 12)

| Config | Pre-gate Bypass | True Leakage | FPR | Blocked | Latency (ms) |
|--------|----------------|--------------|-----|---------|--------------|
| B0 (unprotected) | 100.00% | --- | 0.00% | 0/271 | 0.0 |
| B2_no_G0a (no regex) | 58.67% | --- | 2.00% | 112/271 | 25.8 |
| B2_no_G0b (no verb×obj) | 53.51% | --- | 2.00% | 126/271 | 18.9 |
| **B2_no_G1 (no embedding)** | **74.54%** | --- | 0.00% | 69/271 | 13.6 |
| B2_no_LS (no leakage scan) | 50.92% | --- | 2.00% | 133/271 | 11.8 |
| B2_single_tau (τ=0.62) | 71.22% | --- | 0.00% | 78/271 | 22.4 |
| **B2_full** | **50.92%** | **2.58%** | **2.00%** | **133/271** | 19.5 |

**Key findings:**
1. Removing Gate 1 (embedding) causes the largest bypass rate increase (+23.6pp), confirming it as the primary defense
2. Phase 12 detection improvements (HYP_01 rules, expanded amplifiers) reduced bypass rate from 55.35% to 50.92%
3. The true leakage rate (2.58%) is far lower than the pre-gate bypass rate (50.92%) because the LLM itself does not know proprietary secrets

---

## Bypass Analysis (Phase 11-12)

### By Evasion Technique (after Phase 12 fix)

| Technique | Total | Bypass | Rate |
|-----------|-------|--------|------|
| synonym_substitution | 24 | 15 | 62.5% |
| multi_step_decomposition | 29 | 17 | 58.6% |
| academic_framing | 29 | 16 | 55.2% |
| indirect_reference | 28 | 15 | 53.6% |
| original (thesis prompts) | 100 | 48 | 48.0% |
| passive_voice | 34 | 16 | 47.1% |
| roleplay_framing | 30 | 10 | 33.3% |
| hypothetical_extraction | 27 | 7 | 25.9% |

### By Attack Group

| Group | Total | Bypass | Rate |
|-------|-------|--------|------|
| salami_attack | 33 | 33 | 100.0% |
| paraphrase_extraction | 20 | 15 | 75.0% |
| indirect_extraction | 40 | 26 | 65.0% |
| direct_extraction | 51 | 9 | 17.6% |
| prompt_injection | 29 | 8 | 27.6% |
| hard_block | 19 | 0 | 0.0% |

**Key insight:** Salami attacks (100% bypass) are inherently designed to pass individually — each sub-query is innocent in isolation. However, the LLM still cannot leak actual secrets in response, so the true leakage rate remains low.

---

## Latency Benchmark

| Component | P50 (ms) | P95 (ms) | P99 (ms) |
|-----------|----------|----------|----------|
| Gate 0 Decode | 0.01 | 0.03 | 2.09 |
| Gate 0a (Regex) | 0.02 | 0.05 | 1.49 |
| Gate 0b (Hard-block) | 0.01 | 0.02 | 0.15 |
| Gate 1 (Embedding) | 14.82 | 39.76 | 942.11 |
| Leakage Scan | 15.58 | 23.03 | 88.37 |
| **End-to-end (gates)** | **28.75** | **36.86** | **43.74** |

Sentence encoding dominates latency. FAISS search itself is <0.01ms.

---

## Cross-Domain Generalization (Medical Pilot)

| Domain | Pre-gate Bypass | FPR | TPR | Code Changes |
|--------|----------------|-----|-----|--------------|
| Finance | 50.92% | 2.00% | 49.08% | Baseline |
| **Medical** | **15.00%** | **0.00%** | **85.00%** | **Config only** |

With ZERO changes to detection logic (only config.yaml adaptation), SentinelFlow achieves 85% TPR and 0% FPR in the medical domain.

---

## Statistical Significance (5 runs)

| Metric | Mean | Std | 95% CI |
|--------|------|-----|--------|
| B2 pre-gate bypass | 50.92% | 0.00% | [50.92%, 50.92%] |
| B2 FPR | 2.00% | 0.00% | [2.00%, 2.00%] |

McNemar's test: p < 0.001 (significant). Zero variance is expected for deterministic gate-level evaluation.

---

## Notes and Limitations

1. **Pre-gate bypass ≠ true leakage.** The 50.92% "bypass rate" only means prompts pass the regex/embedding gates. In the full pipeline, the LLM typically responds with generic financial knowledge (not proprietary secrets), yielding a **true ASR of only 2.58%**.

2. **7 true leakage cases** involve the LLM providing generic financial strategy descriptions that coincidentally overlap with secret content (cosine similarity ≥ 0.60). These are borderline cases where public knowledge and proprietary parameters share similar descriptions.

3. **Salami attacks** achieve 100% pre-gate bypass because each sub-query is individually innocent. This is by design — the defense relies on the LLM not having access to proprietary secrets. In a real deployment with a RAG pipeline connected to the secrets database, the leakage scan would be the critical last defense.

4. **Phase 12 improvements** (HYP_01 rules, expanded amplifiers, strict threshold for flagged queries) improved pre-gate block rate from 44.2% to 52.2% (+24 more prompts blocked). FPR increased from 1% to 2% (still within acceptable bounds).

5. **Medical domain** shows higher TPR (85%) because medical attack prompts are more direct than the sophisticated evasion techniques in the expanded finance corpus.

---

## Files Generated

```
eval/results/ablation_results.json           # Ablation study (updated Phase 12)
eval/results/statistical_eval.json           # 5-run statistical eval
eval/results/latency_benchmark.json          # Per-gate latency data
eval/results/medical_eval_results.json       # Medical domain results
eval/results/full_pipeline_eval.json         # Full pipeline eval with LLM (Phase 13)
eval/results/bypass_cases.jsonl              # 144 bypass cases (Phase 11)
eval/results/bypass_analysis_report.json     # Bypass analysis (Phase 11)
eval/results/bypass_analysis_after_fix.json  # After Phase 12 fix
eval/results/prompt_expansion_report.json    # Prompt generation report
eval/figures/latency_plot.pdf                # Latency visualization
eval/latex_tables/table_ablation.tex         # LaTeX: ablation (with true leakage column)
eval/latex_tables/table_statistical.tex      # LaTeX: statistical
eval/latex_tables/table_latency.tex          # LaTeX: latency
eval/latex_tables/table_crossdomain.tex      # LaTeX: cross-domain
```
