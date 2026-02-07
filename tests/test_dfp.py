"""
tests/test_dfp.py

Unit tests for the Digital Fingerprinting module.
"""

import sys
from pathlib import Path

# Ensure repo root importable
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import numpy as np
import pytest

from scripts.dfp import (
    structural_entropy_score,
    cooccurrence_score,
    extract_feature_vector,
    compute_dfp_boost,
    compute_dfp_composite,
    is_allowlisted_only,
    strategy_cluster_distance,
    build_cluster_centroids,
    DEFAULT_FINANCIAL_ALLOWLIST,
)


# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

EMPTY_TEXT = ""
NORMAL_FINANCIAL = "Microsoft reported revenue of $56.5 billion for the quarter, representing a 16% increase year over year."
EDUCATIONAL_RSI = "RSI is a momentum oscillator that measures the speed and magnitude of recent price changes. It ranges from 0 to 100."
SECRET_DENSE = (
    "Buy signal triggers when 14D RSI < 25 AND volume is 2x 20D average. "
    "Position size is 1.5% NAV with 2-day VWAP execution. "
    "Stop at -15% within 30d."
)
STRATEGY_FRAGMENT = (
    "Long top-8% 12M momentum (excl. last month), short bottom-5%. "
    "Rebalance 3rd Friday. Cap 2.8% NAV. Stop: -15% within 30d -> VWAP 3-day liquidation."
)
BENIGN_TERMS_ONLY = "The RSI, MACD, and EBITDA are commonly used financial indicators."


# ---------------------------------------------------------------------------
# 1a. Structural entropy tests
# ---------------------------------------------------------------------------

class TestStructuralEntropy:
    def test_empty(self):
        result = structural_entropy_score(EMPTY_TEXT)
        assert result["char_entropy"] == 0.0
        assert result["word_entropy"] == 0.0
        assert result["numeric_density"] == 0.0
        assert result["entropy_anomaly_score"] == 0.0

    def test_normal_financial(self):
        result = structural_entropy_score(NORMAL_FINANCIAL)
        assert result["char_entropy"] > 0
        assert result["word_entropy"] > 0
        # Normal text has some numeric density
        assert result["numeric_density"] >= 0

    def test_secret_dense_has_higher_numeric_density(self):
        normal = structural_entropy_score(NORMAL_FINANCIAL)
        secret = structural_entropy_score(SECRET_DENSE)
        assert secret["numeric_density"] > normal["numeric_density"]

    def test_secret_has_higher_param_specificity(self):
        secret = structural_entropy_score(SECRET_DENSE)
        assert secret["param_specificity"] > 0

    def test_z_score_anomaly_with_baselines(self):
        baselines = {
            "char_entropy_mean": 4.2,
            "char_entropy_std": 0.5,
            "word_entropy_mean": 8.5,
            "word_entropy_std": 1.0,
            "numeric_density_mean": 0.03,
            "numeric_density_std": 0.02,
            "param_specificity_mean": 0.15,
            "param_specificity_std": 0.08,
        }
        result = structural_entropy_score(SECRET_DENSE, baselines=baselines)
        assert result["entropy_anomaly_score"] > 0

    def test_none_input(self):
        result = structural_entropy_score(None)
        assert result["char_entropy"] == 0.0


# ---------------------------------------------------------------------------
# 1b. Co-occurrence tests
# ---------------------------------------------------------------------------

class TestCooccurrence:
    def test_empty(self):
        result = cooccurrence_score(EMPTY_TEXT)
        assert result["cooccurrence_anomaly_score"] == 0.0
        assert result["per_sentence_density"] == []

    def test_normal_text_low_density(self):
        result = cooccurrence_score(NORMAL_FINANCIAL)
        assert result["cooccurrence_anomaly_score"] < 0.3

    def test_educational_text_low_density(self):
        result = cooccurrence_score(EDUCATIONAL_RSI)
        assert result["cooccurrence_anomaly_score"] < 0.3

    def test_secret_dense_high_density(self):
        result = cooccurrence_score(SECRET_DENSE)
        # Secret text should have significantly higher co-occurrence
        assert result["cooccurrence_anomaly_score"] > 0.1

    def test_strategy_fragment_high_density(self):
        result = cooccurrence_score(STRATEGY_FRAGMENT)
        assert result["cooccurrence_anomaly_score"] > 0.05

    def test_per_sentence_density_length_matches(self):
        result = cooccurrence_score(SECRET_DENSE)
        from scripts.leakage_scan import split_sentences
        sents = split_sentences(SECRET_DENSE)
        assert len(result["per_sentence_density"]) == len(sents)

    def test_cooccurrence_vector_shape(self):
        result = cooccurrence_score(SECRET_DENSE)
        assert len(result["cooccurrence_vector"]) == 5

    def test_custom_weights(self):
        weights = {
            "threshold_operator_weight": 0.5,
            "conjunction_weight": 0.1,
            "actionable_verb_weight": 0.3,
            "time_window_weight": 0.05,
            "position_sizing_weight": 0.05,
        }
        result = cooccurrence_score(SECRET_DENSE, weights=weights)
        assert result["cooccurrence_anomaly_score"] >= 0


# ---------------------------------------------------------------------------
# 1c. Feature vector / clustering tests
# ---------------------------------------------------------------------------

class TestFeatureVector:
    def test_empty_returns_zeros(self):
        vec = extract_feature_vector(EMPTY_TEXT)
        assert vec.shape == (9,)
        assert np.all(vec == 0)

    def test_secret_has_nonzero_features(self):
        vec = extract_feature_vector(SECRET_DENSE)
        assert vec.shape == (9,)
        assert np.any(vec > 0)

    def test_secret_vs_normal_distinguishable(self):
        sec_vec = extract_feature_vector(SECRET_DENSE)
        norm_vec = extract_feature_vector(NORMAL_FINANCIAL)
        # Vectors should differ
        assert not np.allclose(sec_vec, norm_vec)


class TestClusterDistance:
    def test_no_centroids_returns_none(self):
        result = strategy_cluster_distance(SECRET_DENSE)
        assert result["strategy_distance"] is None
        assert result["cluster_suspicion"] is False

    def test_with_mock_centroids(self):
        # Create simple centroids for testing
        strat_centroid = extract_feature_vector(SECRET_DENSE)
        norm_centroid = extract_feature_vector(NORMAL_FINANCIAL)
        cov_inv = np.eye(9)

        # Secret text should be closer to strategy centroid
        result = strategy_cluster_distance(
            SECRET_DENSE, strat_centroid, norm_centroid, cov_inv
        )
        assert result["strategy_distance"] is not None
        assert result["strategy_distance"] < result["normal_distance"]
        assert result["cluster_suspicion"] is True

        # Normal text should be closer to normal centroid
        result2 = strategy_cluster_distance(
            NORMAL_FINANCIAL, strat_centroid, norm_centroid, cov_inv
        )
        assert result2["normal_distance"] < result2["strategy_distance"]
        assert result2["cluster_suspicion"] is False


class TestBuildCentroids:
    def test_build_and_use(self):
        secret_texts = [
            SECRET_DENSE,
            STRATEGY_FRAGMENT,
            "Short when 5D return > +9% AND intraday reversal score > 0.7; cover when z-score < 0.3.",
        ]
        normal_texts = [
            NORMAL_FINANCIAL,
            EDUCATIONAL_RSI,
            "Apple Inc. is a technology company headquartered in Cupertino, California.",
        ]
        strat, norm, cov_inv = build_cluster_centroids(secret_texts, normal_texts)
        assert strat.shape == (9,)
        assert norm.shape == (9,)
        assert cov_inv.shape == (9, 9)


# ---------------------------------------------------------------------------
# 1d. Allowlist tests
# ---------------------------------------------------------------------------

class TestAllowlist:
    def test_benign_terms_only(self):
        assert is_allowlisted_only(BENIGN_TERMS_ONLY) is True

    def test_secret_dense_not_allowlisted(self):
        assert is_allowlisted_only(SECRET_DENSE) is False

    def test_educational_text_is_allowlisted(self):
        assert is_allowlisted_only(EDUCATIONAL_RSI) is True

    def test_empty_text_is_allowlisted(self):
        assert is_allowlisted_only("") is True


# ---------------------------------------------------------------------------
# 1e. DFP fusion helpers
# ---------------------------------------------------------------------------

class TestDFPBoost:
    def test_no_boost_below_soft(self):
        score, elevated = compute_dfp_boost(
            cosine_score=0.50,
            sentence_cooc_density=0.8,
            soft_threshold=0.60,
            hard_threshold=0.70,
        )
        assert score == 0.50
        assert elevated is False

    def test_boost_in_soft_range_with_cooc(self):
        score, elevated = compute_dfp_boost(
            cosine_score=0.63,
            sentence_cooc_density=0.8,
            soft_threshold=0.60,
            hard_threshold=0.70,
            dfp_boost=0.08,
            cooccurrence_threshold=0.65,
        )
        assert score == 0.71  # 0.63 + 0.08
        assert elevated is True

    def test_no_boost_when_cooc_low(self):
        score, elevated = compute_dfp_boost(
            cosine_score=0.63,
            sentence_cooc_density=0.3,
            soft_threshold=0.60,
            hard_threshold=0.70,
        )
        assert score == 0.63
        assert elevated is False

    def test_boost_capped_at_1(self):
        score, elevated = compute_dfp_boost(
            cosine_score=0.95,
            sentence_cooc_density=0.9,
            soft_threshold=0.60,
            hard_threshold=0.70,
            dfp_boost=0.10,
        )
        assert score == 1.0
        assert elevated is True


class TestDFPComposite:
    def test_composite_calculation(self):
        result = compute_dfp_composite(
            entropy_anomaly=0.5,
            cooccurrence_anomaly=0.8,
        )
        expected = 0.35 * 0.5 + 0.65 * 0.8
        assert abs(result - round(expected, 4)) < 1e-4

    def test_composite_zero(self):
        assert compute_dfp_composite(0.0, 0.0) == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
