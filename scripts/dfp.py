"""
scripts/dfp.py

Digital Fingerprinting (DFP) module for SentinelFlow.

Detects strategy leakage through co-occurrence analysis of financial parameters,
structural entropy, and strategy fragment clustering — signals that cosine
similarity alone cannot capture.

Key insight: individual financial terms (RSI, VWAP, NAV) are benign in isolation.
Leakage is signaled by their *co-occurrence* in actionable combinations:
threshold operators + conjunctions + actionable verbs + time windows + sizing rules.
"""

import math
import pickle
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

import numpy as np


# ---------------------------------------------------------------------------
# 1a. Structural entropy scoring
# ---------------------------------------------------------------------------

_NUM_RE = re.compile(r"-?\d+(?:\.\d+)?%?")
_PRECISE_NUM_RE = re.compile(r"\d+\.\d+%?")  # e.g. 1.5%, 0.32, 3.5


def structural_entropy_score(text: str, baselines: Optional[dict] = None) -> dict:
    """
    Compute character-level and word-level Shannon entropy, numeric density,
    and parameter specificity for the given text.

    Returns dict with raw scores and z-score anomaly relative to baselines.
    """
    text = (text or "").strip()
    if not text:
        return {
            "char_entropy": 0.0,
            "word_entropy": 0.0,
            "numeric_density": 0.0,
            "param_specificity": 0.0,
            "entropy_anomaly_score": 0.0,
        }

    # Character-level entropy (bits/char)
    char_counts = Counter(text)
    n_chars = len(text)
    char_entropy = -sum(
        (c / n_chars) * math.log2(c / n_chars)
        for c in char_counts.values()
        if c > 0
    )

    # Word-level entropy (bits/word)
    words = text.lower().split()
    n_words = max(len(words), 1)
    word_counts = Counter(words)
    word_entropy = -sum(
        (c / n_words) * math.log2(c / n_words)
        for c in word_counts.values()
        if c > 0
    )

    # Numeric density
    nums = _NUM_RE.findall(text)
    numeric_density = len(nums) / n_words

    # Parameter specificity: proportion of numbers that are "suspiciously specific"
    # e.g., 1.5% is more specific than "about 10%"
    precise_nums = _PRECISE_NUM_RE.findall(text)
    param_specificity = len(precise_nums) / max(len(nums), 1) if nums else 0.0

    # Compute anomaly score via z-score if baselines provided
    entropy_anomaly = 0.0
    if baselines:
        z_scores = []

        def _z(val, mean_key, std_key):
            m = baselines.get(mean_key, 0.0)
            s = baselines.get(std_key, 1.0)
            if s <= 0:
                s = 1.0
            return (val - m) / s

        z_scores.append(_z(char_entropy, "char_entropy_mean", "char_entropy_std"))
        z_scores.append(_z(word_entropy, "word_entropy_mean", "word_entropy_std"))
        z_scores.append(_z(numeric_density, "numeric_density_mean", "numeric_density_std"))
        z_scores.append(_z(param_specificity, "param_specificity_mean", "param_specificity_std"))

        # Anomaly = mean absolute z-score (higher = more unusual)
        entropy_anomaly = sum(abs(z) for z in z_scores) / len(z_scores)

    return {
        "char_entropy": round(char_entropy, 4),
        "word_entropy": round(word_entropy, 4),
        "numeric_density": round(numeric_density, 4),
        "param_specificity": round(param_specificity, 4),
        "entropy_anomaly_score": round(entropy_anomaly, 4),
    }


# ---------------------------------------------------------------------------
# 1b. Co-occurrence scoring
# ---------------------------------------------------------------------------

# Five discriminating feature patterns
_THRESHOLD_OP_RE = re.compile(r"(?:>=?|<=?|=)\s*\d+(?:\.\d+)?%?")
_CONJUNCTION_RE = re.compile(r"\b(?:AND|OR|IF|THEN|WHEN|WHILE)\b", re.IGNORECASE)
_ACTIONABLE_VERB_RE = re.compile(
    r"\b(?:buy|sell|execute|trigger|exit|hold|rebalance|liquidate|hedge|short|long|enter|cover|close|cut|reduce|increase|allocate|deploy|route)\b",
    re.IGNORECASE,
)
_TIME_WINDOW_RE = re.compile(
    r"\b\d+[- ]?(?:day|D|week|W|month|M|session|trading|minute|hour|year|Y)\b",
    re.IGNORECASE,
)
_POSITION_SIZING_RE = re.compile(
    r"\b\d+(?:\.\d+)?%?\s*(?:NAV|AUM|portfolio|exposure|cap|notional|allocation|gross|net)\b",
    re.IGNORECASE,
)


def _sentence_features(sentence: str) -> np.ndarray:
    """Extract 5-dimensional co-occurrence feature vector for a single sentence."""
    words = sentence.split()
    n_words = max(len(words), 1)

    threshold_ops = len(_THRESHOLD_OP_RE.findall(sentence))
    conjunctions = len(_CONJUNCTION_RE.findall(sentence))
    actionable_verbs = len(_ACTIONABLE_VERB_RE.findall(sentence))
    time_windows = len(_TIME_WINDOW_RE.findall(sentence))
    position_sizing = len(_POSITION_SIZING_RE.findall(sentence))

    # Normalize by sentence length
    return np.array([
        threshold_ops / n_words,
        conjunctions / n_words,
        actionable_verbs / n_words,
        time_windows / n_words,
        position_sizing / n_words,
    ], dtype=np.float64)


def cooccurrence_score(
    text: str,
    weights: Optional[dict] = None,
    density_threshold: float = 0.65,
    financial_allowlist: Optional[List[str]] = None,
) -> dict:
    """
    Compute co-occurrence feature vector per sentence and aggregate.

    The key signal is *simultaneous presence* of multiple feature types —
    a sentence with threshold operators AND actionable verbs AND time windows
    is far more suspicious than one with just a single feature type.

    Returns dict with per-sentence densities and aggregate anomaly score.
    """
    text = (text or "").strip()
    if not text:
        return {
            "cooccurrence_vector": [0.0] * 5,
            "per_sentence_density": [],
            "cooccurrence_anomaly_score": 0.0,
        }

    # Default weights for the 5 features
    w = {
        "threshold_operator_weight": 0.25,
        "conjunction_weight": 0.20,
        "actionable_verb_weight": 0.25,
        "time_window_weight": 0.15,
        "position_sizing_weight": 0.15,
    }
    if weights:
        w.update(weights)

    weight_vec = np.array([
        w["threshold_operator_weight"],
        w["conjunction_weight"],
        w["actionable_verb_weight"],
        w["time_window_weight"],
        w["position_sizing_weight"],
    ], dtype=np.float64)

    # Split into sentences (reuse simple split)
    from scripts.leakage_scan import split_sentences
    sents = split_sentences(text)
    if not sents:
        return {
            "cooccurrence_vector": [0.0] * 5,
            "per_sentence_density": [],
            "cooccurrence_anomaly_score": 0.0,
        }

    per_sentence_density = []
    all_features = []

    for sent in sents:
        feat = _sentence_features(sent)
        all_features.append(feat)

        # Weighted density for this sentence
        density = float(np.dot(feat, weight_vec))

        # Co-occurrence bonus: count how many feature dimensions are non-zero
        active_dims = int(np.sum(feat > 0))
        # Bonus kicks in when 3+ feature types co-occur
        cooc_multiplier = 1.0 + max(0, active_dims - 2) * 0.3

        adjusted_density = density * cooc_multiplier
        per_sentence_density.append(round(adjusted_density, 4))

    # Aggregate co-occurrence vector (mean across sentences)
    agg_vector = np.mean(all_features, axis=0) if all_features else np.zeros(5)

    # Anomaly score: max per-sentence density (catches even a single leaked sentence)
    max_density = max(per_sentence_density) if per_sentence_density else 0.0
    mean_density = float(np.mean(per_sentence_density)) if per_sentence_density else 0.0

    # Weighted combination: max matters more than mean
    cooccurrence_anomaly = 0.7 * max_density + 0.3 * mean_density

    return {
        "cooccurrence_vector": [round(float(v), 4) for v in agg_vector],
        "per_sentence_density": per_sentence_density,
        "cooccurrence_anomaly_score": round(cooccurrence_anomaly, 4),
    }


# ---------------------------------------------------------------------------
# 1c. Strategy fragment clustering
# ---------------------------------------------------------------------------

def extract_feature_vector(text: str) -> np.ndarray:
    """
    Extract a combined feature vector from text for clustering.
    Returns 9-dim vector: [5 co-occurrence features, 4 entropy features].
    """
    from scripts.leakage_scan import split_sentences

    text = (text or "").strip()
    if not text:
        return np.zeros(9, dtype=np.float64)

    # Co-occurrence features (mean across sentences)
    sents = split_sentences(text)
    if sents:
        sent_feats = [_sentence_features(s) for s in sents]
        cooc = np.mean(sent_feats, axis=0)
    else:
        cooc = np.zeros(5, dtype=np.float64)

    # Entropy features
    ent = structural_entropy_score(text)
    entropy_vec = np.array([
        ent["char_entropy"],
        ent["word_entropy"],
        ent["numeric_density"],
        ent["param_specificity"],
    ], dtype=np.float64)

    return np.concatenate([cooc, entropy_vec])


def build_cluster_centroids(
    secret_texts: List[str],
    normal_texts: List[str],
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Compute strategy cluster centroid, normal cluster centroid,
    and covariance matrix for Mahalanobis distance.

    Returns: (strategy_centroid, normal_centroid, cov_inv)
    """
    if not secret_texts:
        raise ValueError("Need at least 1 secret text for clustering")
    if not normal_texts:
        raise ValueError("Need at least 1 normal text for clustering")

    secret_vecs = np.array([extract_feature_vector(t) for t in secret_texts])
    normal_vecs = np.array([extract_feature_vector(t) for t in normal_texts])

    strategy_centroid = np.mean(secret_vecs, axis=0)
    normal_centroid = np.mean(normal_vecs, axis=0)

    # Combined covariance for Mahalanobis
    all_vecs = np.vstack([secret_vecs, normal_vecs])
    cov = np.cov(all_vecs.T)
    # Regularize to avoid singularity
    cov += np.eye(cov.shape[0]) * 1e-6
    cov_inv = np.linalg.inv(cov)

    return strategy_centroid, normal_centroid, cov_inv


def save_centroids(
    strategy_centroid: np.ndarray,
    normal_centroid: np.ndarray,
    cov_inv: np.ndarray,
    strategy_path: str,
    normal_path: str,
):
    """Save cluster centroids and inverse covariance to pickle files."""
    import os
    os.makedirs(os.path.dirname(strategy_path), exist_ok=True)
    os.makedirs(os.path.dirname(normal_path), exist_ok=True)

    with open(strategy_path, "wb") as f:
        pickle.dump({"centroid": strategy_centroid, "cov_inv": cov_inv}, f)
    with open(normal_path, "wb") as f:
        pickle.dump({"centroid": normal_centroid, "cov_inv": cov_inv}, f)


def load_centroids(
    strategy_path: str,
    normal_path: str,
) -> Tuple[Optional[np.ndarray], Optional[np.ndarray], Optional[np.ndarray]]:
    """Load cluster centroids. Returns (strategy_centroid, normal_centroid, cov_inv) or Nones."""
    try:
        with open(strategy_path, "rb") as f:
            strat = pickle.load(f)
        with open(normal_path, "rb") as f:
            norm = pickle.load(f)
        return strat["centroid"], norm["centroid"], strat["cov_inv"]
    except (FileNotFoundError, KeyError):
        return None, None, None


def mahalanobis_distance(x: np.ndarray, centroid: np.ndarray, cov_inv: np.ndarray) -> float:
    """Compute Mahalanobis distance between x and centroid."""
    diff = x - centroid
    return float(np.sqrt(diff @ cov_inv @ diff))


def strategy_cluster_distance(
    text: str,
    strategy_centroid: Optional[np.ndarray] = None,
    normal_centroid: Optional[np.ndarray] = None,
    cov_inv: Optional[np.ndarray] = None,
) -> dict:
    """
    Compute distance of text to strategy vs normal cluster.

    Returns dict with distances and a suspicion flag.
    """
    if strategy_centroid is None or normal_centroid is None or cov_inv is None:
        return {
            "strategy_distance": None,
            "normal_distance": None,
            "cluster_suspicion": False,
            "cluster_ratio": None,
        }

    feat = extract_feature_vector(text)
    d_strat = mahalanobis_distance(feat, strategy_centroid, cov_inv)
    d_norm = mahalanobis_distance(feat, normal_centroid, cov_inv)

    # Suspicion: closer to strategy cluster OR far from both
    ratio = d_strat / max(d_norm, 1e-9)
    cluster_suspicion = ratio < 1.0  # closer to strategy than normal

    return {
        "strategy_distance": round(d_strat, 4),
        "normal_distance": round(d_norm, 4),
        "cluster_suspicion": bool(cluster_suspicion),
        "cluster_ratio": round(ratio, 4),
    }


# ---------------------------------------------------------------------------
# 1d. Two-tier baseline support
# ---------------------------------------------------------------------------

# Tier 1: Static financial vocabulary allowlist (never triggers alone)
DEFAULT_FINANCIAL_ALLOWLIST = [
    "RSI", "MACD", "EBITDA", "P/E", "EPS", "Sharpe", "VWAP", "TWAP",
    "SMA", "EMA", "ATR", "ADV", "NAV", "AUM", "VaR", "VIX", "OBV",
    "ROIC", "FCF", "ROE", "ROA", "PE", "PB", "WACC", "CAPM", "GICS",
    "ETF", "ADR", "IPO", "M&A", "DCA", "FIFO", "LIFO", "GAAP",
    "SEC", "FINRA", "ISDA", "CUSIP", "ISIN", "SEDOL", "Bloomberg",
    "S&P", "NASDAQ", "NYSE", "FTSE", "MSCI", "Russell",
    "Bollinger", "Fibonacci", "Stochastic", "Williams",
    "alpha", "beta", "gamma", "delta", "theta", "vega",
    "drawdown", "Sortino", "Treynor", "Jensen", "Calmar",
]


def is_allowlisted_only(
    text: str,
    allowlist: Optional[List[str]] = None,
) -> bool:
    """
    Check if the text's financial content consists only of allowlisted terms
    (i.e., no actionable parameters). Used to suppress false positives.

    Returns True if the text is likely benign (education/explanation only).
    """
    if allowlist is None:
        allowlist = DEFAULT_FINANCIAL_ALLOWLIST

    # Check if there are actionable patterns present
    has_thresholds = bool(_THRESHOLD_OP_RE.search(text))
    has_sizing = bool(_POSITION_SIZING_RE.search(text))
    has_time_windows = bool(_TIME_WINDOW_RE.search(text))
    has_conjunctions = bool(re.search(r"\b(?:AND|IF|WHEN|THEN)\b", text))

    # If the text has actionable patterns, it's not allowlisted-only
    if has_thresholds and (has_sizing or has_time_windows or has_conjunctions):
        return False

    return True


# ---------------------------------------------------------------------------
# 1e. DFP fusion helpers (used in leakage_scan integration)
# ---------------------------------------------------------------------------

def compute_dfp_boost(
    cosine_score: float,
    sentence_cooc_density: float,
    soft_threshold: float,
    hard_threshold: float,
    dfp_boost: float = 0.08,
    cooccurrence_threshold: float = 0.65,
) -> Tuple[float, bool]:
    """
    Compute DFP-boosted effective score for a single sentence.

    DFP acts as a tiebreaker — it only elevates ambiguous cases (soft range)
    where co-occurrence confirms the leakage pattern.

    Returns: (effective_score, was_elevated)
    """
    # Only boost in the ambiguous soft range
    if cosine_score >= soft_threshold and sentence_cooc_density > cooccurrence_threshold:
        effective = min(cosine_score + dfp_boost, 1.0)
        elevated = effective != cosine_score
        return effective, elevated

    return cosine_score, False


def compute_dfp_composite(
    entropy_anomaly: float,
    cooccurrence_anomaly: float,
    w_entropy: float = 0.35,
    w_cooccurrence: float = 0.65,
) -> float:
    """
    Whole-text DFP composite score for audit/reporting.
    """
    return round(w_entropy * entropy_anomaly + w_cooccurrence * cooccurrence_anomaly, 4)
