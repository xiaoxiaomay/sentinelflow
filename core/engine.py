import os
import time
import uuid
import numpy as np
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from core.config_loader import get_db_params, use_postgres
from sentence_transformers import SentenceTransformer

from dotenv import load_dotenv
load_dotenv()

# 导入你现有的安全与审计模块
from core.audit import HashChainWriter
from scripts.run_rag_with_audit import (
    load_config, rule_gate, embedding_secret_precheck,
    build_prompt, build_fallback_prompt, call_llm, grounding_validate
)
from scripts.leakage_scan import scan_text, load_faiss_index

class SentinelEngine:
    def __init__(self, config_path: str = "config.yaml"):
        # 1. 加载配置
        self.cfg = load_config(config_path)

        # 2. 初始化嵌入模型 (Embedding)
        emb_cfg = self.cfg.get("embedding", {})
        model_name = emb_cfg.get("model_name", "sentence-transformers/all-MiniLM-L6-v2")
        self.embed_model = SentenceTransformer(model_name)

        # 3. 初始化 PostgreSQL 连接 (公开语料) — skip if USE_POSTGRES=false
        self.db_conn = None
        if use_postgres():
            import psycopg2
            from pgvector.psycopg2 import register_vector
            db_params = get_db_params()
            self.db_conn = psycopg2.connect(**db_params)
            register_vector(self.db_conn)

        # 4. 加载本地 FAISS 索引 (私密语料 - 用于安全扫描)
        paths = self.cfg.get("paths", {})
        self.sec_index, self.sec_meta = load_faiss_index(
            paths["secret_index"],
            paths["secret_meta"]
        )

        # 5. 初始化审计记录器 (HashChain)
        audit_cfg = self.cfg.get("audit", {})
        audit_path = Path(audit_cfg.get("out_dir", "data/audit")) / audit_cfg.get("file_name", "audit_log.jsonl")
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        self.writer = HashChainWriter(str(audit_path))

        # 6. 初始化 Salami Session Tracker (if enabled)
        self.salami_tracker = None
        salami_cfg = self.cfg.get("salami_detection", {}) or {}
        if salami_cfg.get("enabled", False):
            from scripts.salami_detector import SalamiSessionTracker
            self.salami_tracker = SalamiSessionTracker(
                window_size=int(salami_cfg.get("window_size", 10)),
                per_query_threshold=float(salami_cfg.get("per_query_threshold", 0.55)),
                session_alert_threshold=float(salami_cfg.get("session_alert_threshold", 0.55)),
                min_targeting_queries=int(salami_cfg.get("min_targeting_queries", 3)),
                gate1_tightening_delta=float(salami_cfg.get("gate1_tightening_delta", 0.05)),
            )
        # Track per-session salami tightening deltas
        self._session_salami_delta: Dict[str, float] = {}

    def _db_retrieve(self, query_vec: np.ndarray, top_k: int = 5) -> List[Dict]:
        """从 PostgreSQL 执行向量检索，并返回标准化的文档格式"""
        if self.db_conn is None:
            return []  # No PostgreSQL — fallback to general knowledge mode
        with self.db_conn.cursor() as cur:
            # 这里的 (1 - distance) 计算余弦相似度分数
            cur.execute("""
                SELECT content, ticker, doc_id, title, 
                       (1 - (embedding <=> %s::vector)) as similarity
                FROM financial_corpus 
                ORDER BY embedding <=> %s::vector 
                LIMIT %s
            """, (query_vec.tolist(), query_vec.tolist(), top_k))
            
            rows = cur.fetchall()
            
            results = []
            for i, r in enumerate(rows):
                results.append({
                    "rank": i + 1,
                    "score": float(r[4]),
                    "text": r[0],
                    "ticker": r[1],     # 股票代码
                    "doc_id": r[2],
                    "title": r[3],
                    "source_type": "public"
                })
            # print(f"the results are : --------{results}")
            return results

    def run_query(self, query: str) -> Dict[str, Any]:
        """主入口：执行完整的安全 RAG 管道"""
        session_id = str(uuid.uuid4())
        start_time = time.time()

        # --- runtime_info ---
        self.writer.append("runtime_info", {
            "session_id": session_id,
            "query": query,
            "stage": "engine_run_query",
            "model": self.cfg.get("embedding", {}).get("model_name", "sentence-transformers/all-MiniLM-L6-v2"),
            "llm_called": False,
        })

        # --- GATE 0 Decode: Encoding detection pre-processor ---
        decode_cfg = self.cfg.get("gate_0_decode", {}) or {}
        if decode_cfg.get("enabled", False):
            from gates.gate_0_decode import decode_gate
            decode_result = decode_gate(query, decode_cfg)
            if decode_result["encoding_detected"]:
                self.writer.append("encoding_detected", {
                    "session_id": session_id,
                    "original_query": query,
                    "decoded_query": decode_result["decoded_text"],
                    "encoding_type": decode_result["encoding_type"],
                })
                query = decode_result["decoded_text"]

        # --- GATE 0: 规则过滤 (意图预检) ---
        gate0_res = rule_gate(query, self.cfg.get("policy", {}))
        self.writer.append("intent_precheck", {"session_id": session_id, "query": query, **gate0_res})
        
        if gate0_res["blocked"]:
            return {
                "answer": self.cfg["policy"].get("block_message", "请求被拦截"),
                "status": "blocked_gate0",
                "session_id": session_id
            }

        # --- GATE 0c: Zero-shot ML Intent Classifier (optional) ---
        gate0c_delta = 0.0
        gate0c_cfg = self.cfg.get("gate_0c", {}) or {}
        if gate0c_cfg.get("enabled", False):
            from gates.gate_0c_intent import gate_0c_classify
            gate0c_res = gate_0c_classify(
                query,
                block_threshold=float(gate0c_cfg.get("block_threshold", 0.75)),
                tighten_threshold=float(gate0c_cfg.get("tighten_threshold", 0.50)),
                tighten_delta=float(gate0c_cfg.get("tighten_delta", 0.10)),
            )
            self.writer.append("gate_0c", {
                "session_id": session_id,
                "query": query,
                **gate0c_res,
            })
            if gate0c_res["blocked"]:
                return {
                    "answer": self.cfg["policy"].get("block_message", "[BLOCKED] Unsafe intent detected."),
                    "status": "blocked_gate0c",
                    "session_id": session_id,
                }
            gate0c_delta = gate0c_res.get("gate1_tighten_delta", 0.0)

        # --- 生成向量 ---
        query_vec = self.embed_model.encode(query, normalize_embeddings=True).astype("float32")

        # --- GATE 1: 私密泄露预检 (对比 Secret FAISS) ---
        # Dual-threshold logic ported from run_rag_with_audit.py
        pre_cfg = self.cfg.get("query_precheck", {})
        if pre_cfg.get("enabled", True):
            base_thr = float(pre_cfg.get("threshold", 0.75))
            sens_thr = float(pre_cfg.get("sensitive_threshold", base_thr))
            strict_thr = float(pre_cfg.get("strict_threshold", sens_thr - 0.05))
            amplifiers = pre_cfg.get("intent_amplifiers", [])
            q_lower = query.lower()
            has_intent = any(amp.lower() in q_lower for amp in amplifiers)
            flagged_strict = gate0_res.get("flagged_for_strict", False)

            if flagged_strict:
                effective_threshold = strict_thr
            elif has_intent:
                effective_threshold = sens_thr
            else:
                effective_threshold = base_thr
            # Apply Gate 0c tightening (stacks with dual-threshold selection)
            if gate0c_delta > 0:
                effective_threshold = max(0.40, effective_threshold - gate0c_delta)

            emb_pre = embedding_secret_precheck(
                self.embed_model, query, self.sec_index, self.sec_meta,
                threshold=effective_threshold,
                top_k=int(pre_cfg.get("top_k_secrets", 3)),
                query_vec=query_vec.reshape(1, -1)
            )
            self.writer.append("query_precheck", {"session_id": session_id, "query": query, **emb_pre})
            if emb_pre["blocked"]:
                return {
                    "answer": pre_cfg.get("block_message", "该话题属于公司机密"),
                    "status": "blocked_gate1",
                    "session_id": session_id
                }

        # --- Salami Session Tracker: detect multi-turn extraction ---
        if self.salami_tracker is not None:
            salami_res = self.salami_tracker.track_query(
                session_id=session_id,
                query_vec=query_vec.reshape(1, -1),
                secret_index=self.sec_index,
                secret_meta=self.sec_meta,
                top_k=int(pre_cfg.get("top_k_secrets", 3)) if pre_cfg else 3,
            )
            self.writer.append("session_salami_check", {
                "session_id": session_id,
                "query": query,
                "session_risk_flag": salami_res["session_risk_flag"],
                "targeted_secrets": salami_res["targeted_secrets"],
            })
            if salami_res["session_risk_flag"]:
                self._session_salami_delta[session_id] = salami_res["recommended_gate1_delta"]

        # --- 核心检索: 从 PostgreSQL 检索公开语料 ---
        rag_cfg = self.cfg.get("rag", {})
        docs = self._db_retrieve(query_vec, top_k=rag_cfg.get("top_k", 5))

        self.writer.append("retrieve", {
            "session_id": session_id,
            "docs_count": len(docs),
            "latency_s": round(time.time() - start_time, 4)
        })

        # --- Fallback decision ---
        fallback_threshold = float(rag_cfg.get("fallback_threshold", 0.40))
        max_retrieval_score = max((d["score"] for d in docs), default=0.0)
        use_grounding = max_retrieval_score >= fallback_threshold
        rag_mode = "rag" if use_grounding else "fallback_general"

        self.writer.append("retrieval_quality", {
            "session_id": session_id,
            "query": query,
            "max_retrieval_score": round(max_retrieval_score, 4),
            "fallback_threshold": fallback_threshold,
            "mode": rag_mode,
        })

        # --- 生成回答 (LLM) ---
        model_name = os.getenv("OPENAI_MODEL") or self.cfg.get("openai_model", "gpt-4o-mini")
        grounding_cfg = self.cfg.get("grounding", {}) or {}
        grounding_threshold = float(grounding_cfg.get("threshold", 0.55))
        grounding_action = str(grounding_cfg.get("action", "redact")).lower()

        if rag_mode == "fallback_general":
            prompt = build_fallback_prompt(query)

            self.writer.append("prompt_built", {
                "session_id": session_id,
                "query": query,
                "prompt_chars": len(prompt),
                "mode": "fallback_general",
                "llm_called": False,
            })

            t_llm = time.time()
            raw_answer = call_llm(prompt, model_name)
            t_llm = time.time() - t_llm

            self.writer.append("llm_response", {
                "session_id": session_id,
                "query": query,
                "model": model_name,
                "latency_s": round(t_llm, 4),
                "raw_answer_chars": len(raw_answer),
                "mode": "fallback_general",
                "llm_called": True,
            })

            # Skip grounding — no docs to ground against
            self.writer.append("grounding_check", {
                "session_id": session_id,
                "query": query,
                "enabled": False,
                "skip_reason": "fallback_general",
                "threshold": grounding_threshold,
                "action": grounding_action,
                "sentences": [],
                "llm_called": True,
            })

            # C4: Prompt distribution monitoring (anomaly detection)
            pm_cfg = self.cfg.get("prompt_monitoring", {}) or {}
            pm_enabled = bool(pm_cfg.get("enabled", False))
            leak_hard_override = None
            leak_soft_override = None

            if pm_enabled:
                from scripts.prompt_monitor import check_anomaly, load_centroid
                try:
                    centroid_data = load_centroid(pm_cfg["centroid_path"])
                    anomaly_result = check_anomaly(
                        query_vec=query_vec.reshape(1, -1),
                        centroid=centroid_data["centroid"],
                        mean_dist=centroid_data["mean_dist"],
                        std_dist=centroid_data["std_dist"],
                        sigma=float(pm_cfg.get("sigma_threshold", 2.0)),
                    )
                    self.writer.append("prompt_monitoring", {
                        "session_id": session_id,
                        "query": query,
                        "anomalous": anomaly_result["anomalous"],
                        "z_score": round(anomaly_result["z_score"], 4),
                        "distance": round(anomaly_result["distance"], 6),
                    })
                    if anomaly_result["anomalous"]:
                        tighten = pm_cfg.get("threshold_tightening", {}) or {}
                        delta_h = float(tighten.get("hard_delta", 0.05))
                        delta_s = float(tighten.get("soft_delta", 0.05))
                        leak_hard_override = max(0.50, float(self.cfg.get("leakage", {}).get("hard_threshold", 0.70)) - delta_h)
                        leak_soft_override = max(0.45, float(self.cfg.get("leakage", {}).get("soft_threshold", 0.60)) - delta_s)
                except Exception as e:
                    self.writer.append("prompt_monitoring", {
                        "session_id": session_id,
                        "query": query,
                        "error": repr(e),
                    })

            # Leakage scan with explicit thresholds (C4 + salami tightening applied)
            leak_cfg = self.cfg.get("leakage", {}) or {}
            dfp_cfg = self.cfg.get("dfp", {}) or {}
            effective_hard = leak_hard_override if leak_hard_override is not None else float(leak_cfg.get("hard_threshold", 0.70))
            effective_soft = leak_soft_override if leak_soft_override is not None else float(leak_cfg.get("soft_threshold", 0.60))
            # Apply salami session tightening (additive with C4)
            salami_delta = self._session_salami_delta.get(session_id, 0.0)
            if salami_delta > 0:
                effective_hard = max(0.50, effective_hard - salami_delta)
                effective_soft = max(0.45, effective_soft - salami_delta)

            leak_res = scan_text(
                text=raw_answer, model=self.embed_model,
                secret_index=self.sec_index, secret_meta=self.sec_meta,
                hard_threshold=effective_hard,
                soft_threshold=effective_soft,
                cascade_k=int(leak_cfg.get("cascade_k", 2)),
                action=str(leak_cfg.get("action", "redact")),
                top_k_secrets=int(leak_cfg.get("top_k_secrets", 1)),
                dfp_enabled=dfp_cfg.get("enabled", False), dfp_config=dfp_cfg,
                grounding_enabled=False,
                grounding_scores=None, grounding_top_docs=None,
            )

            self.writer.append("leakage_scan", {
                "session_id": session_id,
                "query": query,
                "summary": leak_res["summary"],
                "sentences": leak_res["sentences"],
                "redacted_text": leak_res["redacted_text"],
                "mode": "fallback_general",
                "llm_called": True,
            })
        else:
            prompt = build_prompt(query, docs)

            self.writer.append("prompt_built", {
                "session_id": session_id,
                "query": query,
                "prompt_chars": len(prompt),
                "mode": "rag",
                "llm_called": False,
            })

            t_llm = time.time()
            raw_answer = call_llm(prompt, model_name)
            t_llm = time.time() - t_llm

            self.writer.append("llm_response", {
                "session_id": session_id,
                "query": query,
                "model": model_name,
                "latency_s": round(t_llm, 4),
                "raw_answer_chars": len(raw_answer),
                "mode": "rag",
                "llm_called": True,
            })

            # --- 后置审计: Grounding ---
            from scripts.leakage_scan import split_sentences
            g_scores, g_top_docs = grounding_validate(
                self.embed_model, raw_answer, docs,
                threshold=grounding_threshold,
            )

            self.writer.append("grounding_check", {
                "session_id": session_id,
                "query": query,
                "enabled": True,
                "threshold": grounding_threshold,
                "action": grounding_action,
                "sentences": [
                    {
                        "sent_index": i,
                        "text": s,
                        "ground_score": round(float(g_scores[i]), 4) if i < len(g_scores) else None,
                        "ground_doc": g_top_docs[i] if i < len(g_top_docs) else None,
                    }
                    for i, s in enumerate(split_sentences(raw_answer))
                ],
                "llm_called": True,
            })

            # --- C4: Prompt distribution monitoring (anomaly detection) ---
            pm_cfg = self.cfg.get("prompt_monitoring", {}) or {}
            pm_enabled = bool(pm_cfg.get("enabled", False))
            leak_hard_override = None
            leak_soft_override = None

            if pm_enabled:
                from scripts.prompt_monitor import check_anomaly, load_centroid
                try:
                    centroid_data = load_centroid(pm_cfg["centroid_path"])
                    anomaly_result = check_anomaly(
                        query_vec=query_vec.reshape(1, -1),
                        centroid=centroid_data["centroid"],
                        mean_dist=centroid_data["mean_dist"],
                        std_dist=centroid_data["std_dist"],
                        sigma=float(pm_cfg.get("sigma_threshold", 2.0)),
                    )
                    self.writer.append("prompt_monitoring", {
                        "session_id": session_id,
                        "query": query,
                        "anomalous": anomaly_result["anomalous"],
                        "z_score": round(anomaly_result["z_score"], 4),
                        "distance": round(anomaly_result["distance"], 6),
                    })
                    if anomaly_result["anomalous"]:
                        tighten = pm_cfg.get("threshold_tightening", {}) or {}
                        delta_h = float(tighten.get("hard_delta", 0.05))
                        delta_s = float(tighten.get("soft_delta", 0.05))
                        leak_hard_override = max(0.50, float(self.cfg.get("leakage", {}).get("hard_threshold", 0.70)) - delta_h)
                        leak_soft_override = max(0.45, float(self.cfg.get("leakage", {}).get("soft_threshold", 0.60)) - delta_s)
                except Exception as e:
                    self.writer.append("prompt_monitoring", {
                        "session_id": session_id,
                        "query": query,
                        "error": repr(e),
                    })

            # --- Leakage Scan with explicit thresholds (C4 + salami tightening applied) ---
            leak_cfg = self.cfg.get("leakage", {}) or {}
            dfp_cfg = self.cfg.get("dfp", {}) or {}
            effective_hard = leak_hard_override if leak_hard_override is not None else float(leak_cfg.get("hard_threshold", 0.70))
            effective_soft = leak_soft_override if leak_soft_override is not None else float(leak_cfg.get("soft_threshold", 0.60))
            # Apply salami session tightening (additive with C4)
            salami_delta = self._session_salami_delta.get(session_id, 0.0)
            if salami_delta > 0:
                effective_hard = max(0.50, effective_hard - salami_delta)
                effective_soft = max(0.45, effective_soft - salami_delta)

            leak_res = scan_text(
                text=raw_answer, model=self.embed_model,
                secret_index=self.sec_index, secret_meta=self.sec_meta,
                hard_threshold=effective_hard,
                soft_threshold=effective_soft,
                cascade_k=int(leak_cfg.get("cascade_k", 2)),
                action=str(leak_cfg.get("action", "redact")),
                top_k_secrets=int(leak_cfg.get("top_k_secrets", 1)),
                dfp_enabled=dfp_cfg.get("enabled", False), dfp_config=dfp_cfg,
                grounding_scores=g_scores, grounding_top_docs=g_top_docs,
            )

            self.writer.append("leakage_scan", {
                "session_id": session_id,
                "query": query,
                "summary": leak_res["summary"],
                "sentences": leak_res["sentences"],
                "redacted_text": leak_res["redacted_text"],
                "mode": "rag",
                "llm_called": True,
            })

        self.writer.append("final_output", {
            "session_id": session_id,
            "query": query,
            "final_answer": leak_res["redacted_text"],
            "final_answer_chars": len(leak_res["redacted_text"]),
            "mode": rag_mode,
            "leakage_flag": leak_res["summary"]["leakage_flag"],
            "llm_called": True,
        })

        return {
            "answer": leak_res["redacted_text"],
            "status": "success",
            "mode": rag_mode,
            "docs": docs,
            "session_id": session_id,
            "leakage_flag": leak_res["summary"]["leakage_flag"],
            "latency": round(time.time() - start_time, 2)
        }

    def __del__(self):
        """确保程序退出时关闭数据库连接"""
        if hasattr(self, 'db_conn') and self.db_conn is not None:
            self.db_conn.close()