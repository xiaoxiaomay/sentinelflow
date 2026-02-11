#!/usr/bin/env python3
"""
scripts/prompt_monitor.py

C4: Prompt Distribution Monitoring — lightweight behavioral anomaly signal.
Computes centroid of normal query embeddings and checks incoming query distance.
If distance > sigma_threshold * std, flags as anomalous.

Does NOT block queries — only tightens leakage thresholds when anomalous.
"""
import pickle
from typing import Dict

import numpy as np


def compute_centroid(model, prompts: list) -> dict:
    """
    Embed normal prompts, compute centroid, mean distance, std distance.

    Args:
        model: SentenceTransformer model
        prompts: list of query strings

    Returns:
        dict with centroid (np.ndarray), mean_dist (float), std_dist (float)
    """
    embeddings = model.encode(prompts, normalize_embeddings=True)
    embeddings = np.asarray(embeddings, dtype="float32")

    centroid = embeddings.mean(axis=0)
    centroid = centroid / (np.linalg.norm(centroid) + 1e-10)  # re-normalize

    # Cosine distance = 1 - cosine_similarity
    sims = embeddings @ centroid
    distances = 1.0 - sims

    return {
        "centroid": centroid,
        "mean_dist": float(distances.mean()),
        "std_dist": float(distances.std()),
        "n_prompts": len(prompts),
    }


def check_anomaly(
    query_vec: np.ndarray,
    centroid: np.ndarray,
    mean_dist: float,
    std_dist: float,
    sigma: float = 2.0,
) -> Dict[str, object]:
    """
    Check if query embedding is anomalous vs normal profile.

    Args:
        query_vec: query embedding (1D or 2D array)
        centroid: centroid of normal queries
        mean_dist: mean cosine distance of normal queries from centroid
        std_dist: std of cosine distances
        sigma: number of standard deviations for anomaly threshold

    Returns:
        dict with anomalous (bool), z_score (float), distance (float)
    """
    qv = query_vec.flatten()
    sim = float(np.dot(qv, centroid))
    distance = 1.0 - sim

    if std_dist < 1e-10:
        z_score = 0.0
    else:
        z_score = (distance - mean_dist) / std_dist

    return {
        "anomalous": z_score > sigma,
        "z_score": z_score,
        "distance": distance,
    }


def load_centroid(path: str) -> dict:
    """Load precomputed centroid from pickle."""
    with open(path, "rb") as f:
        return pickle.load(f)


def save_centroid(data: dict, path: str):
    """Save centroid to pickle."""
    with open(path, "wb") as f:
        pickle.dump(data, f)
