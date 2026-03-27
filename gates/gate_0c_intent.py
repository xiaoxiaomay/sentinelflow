"""
gates/gate_0c_intent.py

Gate 0c: Zero-shot ML Intent Classifier for SentinelFlow.

Sits between Gate 0b and Gate 1. Uses DeBERTa-v3-large-MNLI for
zero-shot classification of query intent without any fine-tuning.

Always fails open (returns allow on any exception) to avoid
blocking legitimate queries due to model loading failures.
"""
import time
from typing import Any, Dict

_CLASSIFIER = None


def _get_classifier(model_name: str = "MoritzLaurer/DeBERTa-v3-large-mnli-fever-anli-ling-wanli"):
    """Lazy-load the zero-shot classifier (only loaded once, on first call)."""
    global _CLASSIFIER
    if _CLASSIFIER is None:
        from transformers import pipeline
        _CLASSIFIER = pipeline(
            "zero-shot-classification",
            model=model_name,
            device=-1,  # CPU only
        )
    return _CLASSIFIER


LABELS = [
    "financial data extraction",
    "system prompt theft",
    "legitimate financial analysis",
    "general question",
]

BLOCK_LABELS = {"financial data extraction", "system prompt theft"}


def gate_0c_classify(
    query: str,
    block_threshold: float = 0.75,
    tighten_threshold: float = 0.50,
    tighten_delta: float = 0.10,
    model_name: str = "MoritzLaurer/DeBERTa-v3-large-mnli-fever-anli-ling-wanli",
) -> Dict[str, Any]:
    """
    Zero-shot intent classification using DeBERTa-large-MNLI.

    Args:
        query: The user query to classify.
        block_threshold: If top malicious label score >= this, block.
        tighten_threshold: If top malicious label score >= this (but < block),
                          tighten Gate 1 threshold by tighten_delta.
        tighten_delta: Amount to subtract from Gate 1 threshold when tightening.
        model_name: HuggingFace model ID for zero-shot classifier.

    Returns:
        {
            "blocked": bool,
            "top_label": str,
            "top_score": float,
            "all_scores": dict,
            "gate1_tighten_delta": float,  # 0.0 if no tightening needed
            "decision": "block" | "tighten" | "allow",
            "latency_ms": float,
        }
    """
    t_start = time.time()
    try:
        clf = _get_classifier(model_name)
        result = clf(query, LABELS, multi_label=False)

        scores = dict(zip(result["labels"], result["scores"]))
        top_label = result["labels"][0]
        top_score = result["scores"][0]

        blocked = False
        delta = 0.0
        decision = "allow"

        if top_label in BLOCK_LABELS:
            if top_score >= block_threshold:
                blocked = True
                decision = "block"
            elif top_score >= tighten_threshold:
                delta = tighten_delta
                decision = "tighten"

        latency_ms = round((time.time() - t_start) * 1000, 1)

        return {
            "blocked": blocked,
            "top_label": top_label,
            "top_score": round(top_score, 4),
            "all_scores": {k: round(v, 4) for k, v in scores.items()},
            "gate1_tighten_delta": delta,
            "decision": decision,
            "latency_ms": latency_ms,
        }
    except Exception as e:
        # Fail open: never block on model failure
        latency_ms = round((time.time() - t_start) * 1000, 1)
        return {
            "blocked": False,
            "top_label": "unknown",
            "top_score": 0.0,
            "all_scores": {},
            "gate1_tighten_delta": 0.0,
            "decision": "allow",
            "latency_ms": latency_ms,
            "error": str(e),
        }
