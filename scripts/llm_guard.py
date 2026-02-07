"""
scripts/llm_guard.py

Llama Guard / PromptGuard integration for SentinelFlow.

Provides ML-based semantic classification of queries to catch
sophisticated rephrased attacks and social engineering that regex
rules cannot detect.

Supports multiple backends:
  - "promptguard": Meta Prompt-Guard-86M (lightweight, CPU-friendly)
  - "llamaguard3": Llama Guard 3 8B (GPU or API-hosted)
  - "api": External API endpoint (Together.ai, Fireworks, etc.)

Usage:
    result = llm_guard(query, config)
    # result: {blocked: bool, categories: list, score: float, latency_s: float, error: str|None}
"""

import time
from typing import Any, Dict, Optional


def llm_guard(query: str, config: dict) -> Dict[str, Any]:
    """
    Run ML-based guard classification on a query.

    Args:
        query: The user query to classify
        config: Guard configuration dict with keys:
            - enabled: bool
            - backend: "promptguard" | "llamaguard3" | "api"
            - model_path: str (HuggingFace model ID or API endpoint)
            - timeout_s: float
            - fail_mode: "closed" | "open"
            - categories: list of category IDs to enforce

    Returns:
        {
            blocked: bool,
            categories: list,     # matched category IDs
            score: float,         # confidence score 0-1
            latency_s: float,
            error: str | None,    # error message if backend failed
            backend: str,
        }
    """
    config = config or {}
    enabled = config.get("enabled", False)
    if not enabled:
        return {
            "blocked": False,
            "categories": [],
            "score": 0.0,
            "latency_s": 0.0,
            "error": None,
            "backend": "disabled",
        }

    backend = config.get("backend", "promptguard")
    fail_mode = config.get("fail_mode", "closed")
    timeout_s = float(config.get("timeout_s", 2.0))

    t0 = time.time()

    try:
        if backend == "promptguard":
            result = _run_promptguard(query, config, timeout_s)
        elif backend == "llamaguard3":
            result = _run_llamaguard3(query, config, timeout_s)
        elif backend == "api":
            result = _run_api_guard(query, config, timeout_s)
        else:
            result = {
                "blocked": fail_mode == "closed",
                "categories": [],
                "score": 0.0,
                "error": f"Unknown backend: {backend}",
            }
    except Exception as e:
        # Fail-closed or fail-open based on config
        blocked = fail_mode == "closed"
        result = {
            "blocked": blocked,
            "categories": [],
            "score": 0.0,
            "error": f"guard_error: {repr(e)}",
        }

    result["latency_s"] = round(time.time() - t0, 4)
    result["backend"] = backend
    result.setdefault("error", None)

    return result


# ---------------------------------------------------------------------------
# Backend: PromptGuard (Meta Prompt-Guard-86M)
# ---------------------------------------------------------------------------

# Module-level cache for the loaded model/tokenizer
_promptguard_model = None
_promptguard_tokenizer = None


def _load_promptguard(model_path: str):
    """Load PromptGuard model and tokenizer (cached after first load)."""
    global _promptguard_model, _promptguard_tokenizer

    if _promptguard_model is not None:
        return _promptguard_model, _promptguard_tokenizer

    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    import torch

    _promptguard_tokenizer = AutoTokenizer.from_pretrained(model_path)
    _promptguard_model = AutoModelForSequenceClassification.from_pretrained(model_path)
    _promptguard_model.eval()

    return _promptguard_model, _promptguard_tokenizer


def _run_promptguard(query: str, config: dict, timeout_s: float) -> dict:
    """
    Run PromptGuard classification.

    PromptGuard-86M outputs 3 classes:
      0 = benign, 1 = injection, 2 = jailbreak

    We block on class 1 (injection) or class 2 (jailbreak).
    """
    import torch

    model_path = config.get("model_path", "meta-llama/Prompt-Guard-86M")

    model, tokenizer = _load_promptguard(model_path)

    inputs = tokenizer(
        query,
        return_tensors="pt",
        truncation=True,
        max_length=512,
        padding=True,
    )

    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probs = torch.softmax(logits, dim=-1)[0]

    # Class mapping: 0=benign, 1=injection, 2=jailbreak
    benign_prob = float(probs[0])
    injection_prob = float(probs[1]) if len(probs) > 1 else 0.0
    jailbreak_prob = float(probs[2]) if len(probs) > 2 else 0.0

    max_threat_prob = max(injection_prob, jailbreak_prob)
    predicted_class = int(torch.argmax(probs))

    categories = []
    if predicted_class == 1:
        categories.append("injection")
    elif predicted_class == 2:
        categories.append("jailbreak")

    blocked = predicted_class != 0

    return {
        "blocked": blocked,
        "categories": categories,
        "score": round(max_threat_prob, 4),
        "details": {
            "benign_prob": round(benign_prob, 4),
            "injection_prob": round(injection_prob, 4),
            "jailbreak_prob": round(jailbreak_prob, 4),
            "predicted_class": predicted_class,
        },
    }


# ---------------------------------------------------------------------------
# Backend: Llama Guard 3 (8B)
# ---------------------------------------------------------------------------

def _run_llamaguard3(query: str, config: dict, timeout_s: float) -> dict:
    """
    Run Llama Guard 3 classification.

    Requires a GPU or quantized model. Falls back to fail-mode if not available.
    """
    model_path = config.get("model_path", "meta-llama/Llama-Guard-3-8B")
    enforced_categories = set(config.get("categories", []))

    try:
        from transformers import AutoTokenizer, AutoModelForCausalLM
        import torch

        tokenizer = AutoTokenizer.from_pretrained(model_path)
        model = AutoModelForCausalLM.from_pretrained(
            model_path,
            torch_dtype=torch.float16,
            device_map="auto",
        )

        # Format as Llama Guard conversation
        chat = [
            {"role": "user", "content": query},
        ]
        input_ids = tokenizer.apply_chat_template(
            chat, return_tensors="pt"
        ).to(model.device)

        with torch.no_grad():
            output = model.generate(
                input_ids=input_ids,
                max_new_tokens=100,
                pad_token_id=tokenizer.eos_token_id,
            )

        response = tokenizer.decode(
            output[0][input_ids.shape[-1]:],
            skip_special_tokens=True,
        ).strip()

        # Parse Llama Guard output: "safe" or "unsafe\nS1,S2,..."
        is_safe = response.lower().startswith("safe")
        categories = []
        if not is_safe:
            lines = response.split("\n")
            for line in lines[1:]:
                cats = [c.strip() for c in line.split(",") if c.strip()]
                categories.extend(cats)

        # Filter to enforced categories
        if enforced_categories:
            relevant = [c for c in categories if c in enforced_categories]
            blocked = len(relevant) > 0
            categories = relevant
        else:
            blocked = not is_safe

        return {
            "blocked": blocked,
            "categories": categories,
            "score": 1.0 if blocked else 0.0,
            "raw_response": response,
        }

    except ImportError:
        return {
            "blocked": config.get("fail_mode", "closed") == "closed",
            "categories": [],
            "score": 0.0,
            "error": "llamaguard3 requires GPU-capable transformers installation",
        }
    except Exception as e:
        return {
            "blocked": config.get("fail_mode", "closed") == "closed",
            "categories": [],
            "score": 0.0,
            "error": f"llamaguard3_error: {repr(e)}",
        }


# ---------------------------------------------------------------------------
# Backend: API-based guard (Together.ai, Fireworks, etc.)
# ---------------------------------------------------------------------------

def _run_api_guard(query: str, config: dict, timeout_s: float) -> dict:
    """
    Call an external guard API endpoint.

    Expects config keys:
      - model_path: API endpoint URL
      - api_key: (optional) bearer token
      - model_name: (optional) model name to pass in request body
    """
    import requests

    endpoint = config.get("model_path", "")
    api_key = config.get("api_key", "")
    model_name = config.get("model_name", "meta-llama/Llama-Guard-3-8B")

    if not endpoint:
        return {
            "blocked": config.get("fail_mode", "closed") == "closed",
            "categories": [],
            "score": 0.0,
            "error": "No API endpoint configured for guard.model_path",
        }

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload = {
        "model": model_name,
        "messages": [{"role": "user", "content": query}],
        "max_tokens": 100,
    }

    try:
        resp = requests.post(
            endpoint,
            json=payload,
            headers=headers,
            timeout=timeout_s,
        )
        resp.raise_for_status()
        data = resp.json()

        # Parse response (OpenAI-compatible format)
        content = ""
        choices = data.get("choices", [])
        if choices:
            content = choices[0].get("message", {}).get("content", "")

        is_safe = content.lower().startswith("safe")
        categories = []
        if not is_safe:
            lines = content.split("\n")
            for line in lines[1:]:
                cats = [c.strip() for c in line.split(",") if c.strip()]
                categories.extend(cats)

        enforced = set(config.get("categories", []))
        if enforced:
            categories = [c for c in categories if c in enforced]

        blocked = len(categories) > 0 if enforced else not is_safe

        return {
            "blocked": blocked,
            "categories": categories,
            "score": 1.0 if blocked else 0.0,
        }

    except requests.Timeout:
        return {
            "blocked": config.get("fail_mode", "closed") == "closed",
            "categories": [],
            "score": 0.0,
            "error": "guard_api_timeout",
        }
    except Exception as e:
        return {
            "blocked": config.get("fail_mode", "closed") == "closed",
            "categories": [],
            "score": 0.0,
            "error": f"guard_api_error: {repr(e)}",
        }
