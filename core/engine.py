import os
import time
import uuid
import numpy as np
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor

from dotenv import load_dotenv
load_dotenv()

from core.audit import HashChainWriter
from scripts.run_rag_with_audit import (
    load_config, rule_gate, embedding_secret_precheck,
    retrieve_topk, build_prompt, call_llm, grounding_validate
)
from scripts.leakage_scan import scan_text, load_faiss_index

class SentinelEngine:
    def __init__(self, config_path: str = "config.yaml"):
        self.cfg = load_config(config_path)
        self.paths = self.cfg.get("paths", {})
        
        # 1. 加载模型
        from sentence_transformers import SentenceTransformer
        model_name = self.cfg.get("embedding", {}).get("model_name", "sentence-transformers/all-MiniLM-L6-v2")
        self.embed_model = SentenceTransformer(model_name)
        
        # 2. 加载索引
        self.pub_index, self.pub_meta = load_faiss_index(self.paths["public_index"], self.paths["public_meta"])
        self.sec_index, self.sec_meta = load_faiss_index(self.paths["secret_index"], self.paths["secret_meta"])
        
        # 3. 初始化审计
        audit_cfg = self.cfg.get("audit", {})
        audit_path = Path(audit_cfg.get("out_dir", "data/audit")) / audit_cfg.get("file_name", "audit_log.jsonl")
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        self.writer = HashChainWriter(str(audit_path))

    def run_query(self, query: str) -> Dict[str, Any]:
        session_id = str(uuid.uuid4())
        
        # --- Gate 0: RuleGate ---
        gate0_res = rule_gate(query, self.cfg.get("policy", {}))
        self.writer.append("intent_precheck", {"session_id": session_id, "query": query, **gate0_res})
        
        if gate0_res["blocked"]:
            return {"answer": self.cfg["policy"].get("block_message"), "status": "blocked_gate0"}

        # --- Embedding (Shared) ---
        query_vec = self.embed_model.encode([query], normalize_embeddings=True).astype("float32")

        # --- Gate 1: Secret Precheck ---
        pre_cfg = self.cfg.get("query_precheck", {})
        if pre_cfg.get("enabled", True):
            emb_pre = embedding_secret_precheck(
                self.embed_model, query, self.sec_index, self.sec_meta,
                threshold=pre_cfg.get("threshold", 0.60), query_vec=query_vec
            )
            self.writer.append("query_precheck", {"session_id": session_id, **emb_pre})
            if emb_pre["blocked"]:
                return {"answer": pre_cfg.get("block_message"), "status": "blocked_gate1"}

        # --- Retrieval & RAG ---
        rag_cfg = self.cfg.get("rag", {})
        docs, rerank_info = retrieve_topk(
            self.embed_model, self.pub_index, self.pub_meta, query,
            top_k=rag_cfg.get("top_k", 5), query_vec=query_vec
        )
        
        prompt = build_prompt(query, docs)
        model_name = os.getenv("OPENAI_MODEL") or self.cfg.get("openai_model", "gpt-4o-mini")
        raw_answer = call_llm(prompt, model_name)

        # --- Post-Check: Leakage Scan & DFP ---
        leak_cfg = self.cfg.get("leakage", {})
        dfp_cfg = self.cfg.get("dfp", {})
        leak_res = scan_text(
            text=raw_answer, model=self.embed_model, 
            secret_index=self.sec_index, secret_meta=self.sec_meta,
            dfp_enabled=dfp_cfg.get("enabled", False), dfp_config=dfp_cfg
        )
        
        self.writer.append("final_output", {"session_id": session_id, "final_answer": leak_res["redacted_text"]})
        
        return {
            "answer": leak_res["redacted_text"],
            "status": "success",
            "docs": docs,
            "leakage_flag": leak_res["summary"]["leakage_flag"]
        }