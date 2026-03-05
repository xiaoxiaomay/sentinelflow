import os
import time
import uuid
import numpy as np
import psycopg2
from pgvector.psycopg2 import register_vector
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from core.config_loader import get_db_params
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

        # 3. 初始化 PostgreSQL 连接 (公开语料)
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

    def _db_retrieve(self, query_vec: np.ndarray, top_k: int = 5) -> List[Dict]:
        """从 PostgreSQL 执行向量检索，并返回标准化的文档格式"""
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

        # --- GATE 0: 规则过滤 (意图预检) ---
        gate0_res = rule_gate(query, self.cfg.get("policy", {}))
        self.writer.append("intent_precheck", {"session_id": session_id, "query": query, **gate0_res})
        
        if gate0_res["blocked"]:
            return {
                "answer": self.cfg["policy"].get("block_message", "请求被拦截"),
                "status": "blocked_gate0",
                "session_id": session_id
            }

        # --- 生成向量 ---
        query_vec = self.embed_model.encode(query, normalize_embeddings=True).astype("float32")

        # --- GATE 1: 私密泄露预检 (对比 Secret FAISS) ---
        pre_cfg = self.cfg.get("query_precheck", {})
        if pre_cfg.get("enabled", True):
            # 注意：此处 query_vec 需要 reshape 以匹配 FAISS 期望的输入
            emb_pre = embedding_secret_precheck(
                self.embed_model, query, self.sec_index, self.sec_meta,
                threshold=float(pre_cfg.get("threshold", 0.60)),
                query_vec=query_vec.reshape(1, -1)
            )
            self.writer.append("query_precheck", {"session_id": session_id, "query": query, **emb_pre})
            if emb_pre["blocked"]:
                return {
                    "answer": pre_cfg.get("block_message", "该话题属于公司机密"),
                    "status": "blocked_gate1",
                    "session_id": session_id
                }

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

            # Leakage scan still runs
            leak_cfg = self.cfg.get("leakage", {})
            dfp_cfg = self.cfg.get("dfp", {})
            leak_res = scan_text(
                text=raw_answer, model=self.embed_model,
                secret_index=self.sec_index, secret_meta=self.sec_meta,
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

            # --- Leakage Scan ---
            leak_cfg = self.cfg.get("leakage", {})
            dfp_cfg = self.cfg.get("dfp", {})
            leak_res = scan_text(
                text=raw_answer, model=self.embed_model,
                secret_index=self.sec_index, secret_meta=self.sec_meta,
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
        if hasattr(self, 'db_conn'):
            self.db_conn.close()