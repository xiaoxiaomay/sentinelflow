#!/usr/bin/env python3
"""
scripts/generate_secrets.py

Expands the secret corpus from ~40 hand-crafted records to 150-200 records
using Quantpedia-seeded templates with specific implementation parameters.

Covers 9 strategy archetypes with 3 sensitivity levels.

Usage:
    python scripts/generate_secrets.py --output data/secrets/secrets.jsonl --mode append
    python scripts/generate_secrets.py --output data/secrets/secrets.jsonl --mode overwrite
"""

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# ---------------------------------------------------------------------------
# Template-based secret generation
# Each template is a dict with:
#   _id, title, text, source_type, trust_score, sensitivity_level,
#   category, tags, strategy_archetype, parameter_count, has_threshold_conditions
# ---------------------------------------------------------------------------

GENERATED_SECRETS = [
    # =========================================================================
    # MOMENTUM (15 records)
    # =========================================================================
    {
        "_id": "S0041", "title": "Momentum: Cross-Sectional 12M",
        "text": "Confidential: Alpha-MOM-01: Long top-8% 12M momentum (excl. last month), short bottom-5%. Universe: Liq-500. Rebalance 3rd Friday. Cap 2.8% NAV. Stop: -15% within 30d -> VWAP 3-day liquidation.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "momentum",
        "tags": ["momentum", "cross-sectional", "long-short"], "parameter_count": 7, "has_threshold_conditions": True,
    },
    {
        "_id": "S0042", "title": "Momentum: Time-Series Trend Filter",
        "text": "Confidential: Alpha-MOM-02: Go long when price > 200D SMA AND 50D SMA > 200D SMA. Size: 1.2% NAV per name. Exit when price closes below 50D SMA for 3 consecutive days.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "momentum",
        "tags": ["momentum", "trend", "sma"], "parameter_count": 5, "has_threshold_conditions": True,
    },
    {
        "_id": "S0043", "title": "Momentum: Dual-Momentum Overlay",
        "text": "Confidential: Alpha-MOM-03: Apply dual-momentum: relative (top 20% 6M return among sector peers) AND absolute (6M return > T-bill + 2%). Rotate monthly. Max 15 names, equal weight.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "momentum",
        "tags": ["momentum", "dual", "rotation"], "parameter_count": 5, "has_threshold_conditions": True,
    },
    {
        "_id": "S0044", "title": "Momentum: 52-Week High Proximity",
        "text": "Confidential: Alpha-MOM-04: Long when price is within 5% of 52W high AND volume > 1.3x 20D avg. Hold 15 trading days. Stop at -8% from entry.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "momentum",
        "tags": ["momentum", "52w-high", "volume"], "parameter_count": 5, "has_threshold_conditions": True,
    },
    {
        "_id": "S0045", "title": "Momentum: Industry Momentum Spread",
        "text": "Confidential: Alpha-MOM-05: Long top-3 industries by 3M return, short bottom-3. Use ETF proxies for execution. Rebalance bi-weekly. Gross 80% notional.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "momentum",
        "tags": ["momentum", "industry", "rotation"], "parameter_count": 4, "has_threshold_conditions": False,
    },
    {
        "_id": "S0046", "title": "Momentum: Post-Earnings Momentum",
        "text": "Confidential: Alpha-MOM-06: Long names with positive earnings surprise > 5% AND positive 5D post-earnings drift. Entry T+2 after report. Hold 20D. Max 1.5% NAV per name.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "momentum",
        "tags": ["momentum", "earnings", "drift"], "parameter_count": 5, "has_threshold_conditions": True,
    },
    {
        "_id": "S0047", "title": "Momentum: Relative Strength Index Combo",
        "text": "Confidential: Alpha-MOM-07: Long when 14D RSI crosses above 30 from below AND MACD histogram turns positive. Size 1.0% NAV. Trail stop at 2x ATR(14).",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "momentum",
        "tags": ["momentum", "rsi", "macd", "atr"], "parameter_count": 5, "has_threshold_conditions": True,
    },
    {
        "_id": "S0048", "title": "Momentum: Factor Momentum",
        "text": "Confidential: Alpha-MOM-08: Overweight factors with positive 12M returns (momentum, quality, value). Rebalance quarterly. Target 120% gross. Underweight factors with negative 12M return by 50%.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "momentum",
        "tags": ["momentum", "factor", "rebalance"], "parameter_count": 4, "has_threshold_conditions": False,
    },
    {
        "_id": "S0049", "title": "Momentum: Acceleration Filter",
        "text": "Confidential: Alpha-MOM-09: Enter when 1M return > 3M return/3 (acceleration positive) AND 6M return > 0. Exit on deceleration for 2 consecutive weeks.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "momentum",
        "tags": ["momentum", "acceleration", "filter"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0050", "title": "Momentum: Gap-Up Continuation",
        "text": "Confidential: Alpha-MOM-10: Long when opening gap > +2.5% on volume > 2x 20D avg. Entry at first 15-min VWAP. Hold 5D. Stop at gap-fill (previous close).",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "momentum",
        "tags": ["momentum", "gap", "intraday"], "parameter_count": 5, "has_threshold_conditions": True,
    },
    {
        "_id": "S0051", "title": "Momentum: Short-Term Reversal Exclusion",
        "text": "Confidential: Alpha-MOM-11: Standard 12-1 momentum but exclude names with 1W return > +10% (short-term reversal filter). Reduces max drawdown by ~3% historically.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "momentum",
        "tags": ["momentum", "reversal", "filter"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0052", "title": "Momentum: Volume-Weighted Momentum",
        "text": "Confidential: Alpha-MOM-12: Rank by volume-weighted price change over 20D (sum of daily return * relative volume). Long top quintile, short bottom quintile.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "momentum",
        "tags": ["momentum", "volume-weighted", "ranking"], "parameter_count": 3, "has_threshold_conditions": False,
    },
    {
        "_id": "S0053", "title": "Momentum: Sector-Neutral Momentum",
        "text": "Confidential: Alpha-MOM-13: Within each GICS sector, long top-10% 6M momentum, short bottom-10%. Ensures sector neutrality. Rebalance monthly. Position cap 2.0% NAV.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "momentum",
        "tags": ["momentum", "sector-neutral", "gics"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0054", "title": "Momentum: Low-Vol Momentum Intersection",
        "text": "Confidential: Alpha-MOM-14: Long names in top-30% momentum AND bottom-30% 60D realized vol. Historically 1.5x Sharpe vs pure momentum. Rebalance bi-weekly.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "momentum",
        "tags": ["momentum", "low-vol", "intersection"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0055", "title": "Momentum: Earnings Revision Momentum",
        "text": "Confidential: Alpha-MOM-15: Long when FY1 EPS estimate revised up > 3% in past 30D by >= 2 analysts. Short when revised down > 3% by >= 2 analysts. Hold 20D.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "momentum",
        "tags": ["momentum", "revisions", "analysts"], "parameter_count": 5, "has_threshold_conditions": True,
    },

    # =========================================================================
    # MEAN REVERSION (15 records)
    # =========================================================================
    {
        "_id": "S0056", "title": "Mean Reversion: Bollinger Band Bounce",
        "text": "Confidential: Alpha-MR-01: Long when price touches lower Bollinger Band (20D, 2.0 sigma) AND RSI(14) < 30. Exit at middle band. Stop at -3% from entry.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "mean_reversion",
        "tags": ["mean_reversion", "bollinger", "rsi"], "parameter_count": 5, "has_threshold_conditions": True,
    },
    {
        "_id": "S0057", "title": "Mean Reversion: Pairs Trading - Coke/Pepsi",
        "text": "Confidential: Alpha-MR-02: Trade KO/PEP pair when spread z-score > 2.0 (short outperformer, long underperformer). Close at z < 0.5. Lookback 60D. Size 1.0% NAV per leg.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "mean_reversion",
        "tags": ["mean_reversion", "pairs", "zscore"], "parameter_count": 5, "has_threshold_conditions": True,
    },
    {
        "_id": "S0058", "title": "Mean Reversion: Ornstein-Uhlenbeck Model",
        "text": "Confidential: Alpha-MR-03: Fit OU process to log-price spread of cointegrated pairs. Enter when spread > 1.5x estimated sigma. Half-life must be < 15D for trade viability.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "mean_reversion",
        "tags": ["mean_reversion", "ou_process", "cointegration"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0059", "title": "Mean Reversion: RSI Oversold Bounce",
        "text": "Confidential: Alpha-MR-04: Long when RSI(2) < 10 on S&P 500 constituents. Exit when RSI(2) > 65. Historical win rate ~80%. Max 20 simultaneous positions.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "mean_reversion",
        "tags": ["mean_reversion", "rsi", "short-term"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0060", "title": "Mean Reversion: ETF Premium/Discount",
        "text": "Confidential: Alpha-MR-05: Trade ETF vs NAV when premium/discount > 0.8%. Long ETF when discount > 0.8%, short when premium > 0.8%. Intraday execution via limit orders.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "mean_reversion",
        "tags": ["mean_reversion", "etf", "arbitrage"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0061", "title": "Mean Reversion: Sector Spread Convergence",
        "text": "Confidential: Alpha-MR-06: When XLF/XLK ratio deviates > 1.8 sigma from 60D mean, go long underperformer, short outperformer. Convergence expected within 10-15D.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "mean_reversion",
        "tags": ["mean_reversion", "sector", "ratio"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0062", "title": "Mean Reversion: Overnight Return Reversal",
        "text": "Confidential: Alpha-MR-07: Short names with overnight gap > +3% at open, cover at MOC. Long names with overnight gap < -3% at open. Size: 0.5% NAV per trade.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "mean_reversion",
        "tags": ["mean_reversion", "overnight", "gap"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0063", "title": "Mean Reversion: VIX Term Structure",
        "text": "Confidential: Alpha-MR-08: Long VIX futures when contango > 8% (front vs 2nd month) expecting normalization. Max loss: 4% of allocation. Roll 5D before expiry.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "mean_reversion",
        "tags": ["mean_reversion", "vix", "term_structure"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0064", "title": "Mean Reversion: Intraday VWAP Reversion",
        "text": "Confidential: Alpha-MR-09: Buy when price is > 1.5% below VWAP in first 2 hours of trading. Target return to VWAP. Stop at -2% from entry. Large caps only.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "mean_reversion",
        "tags": ["mean_reversion", "vwap", "intraday"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0065", "title": "Mean Reversion: Relative Value Basket",
        "text": "Confidential: Alpha-MR-10: Construct basket of 5 most underperforming names vs sector over 10D. Go long basket, short sector ETF. Hold 5D. Rebalance daily.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "mean_reversion",
        "tags": ["mean_reversion", "basket", "relative_value"], "parameter_count": 4, "has_threshold_conditions": False,
    },
    {
        "_id": "S0066", "title": "Mean Reversion: Moving Average Envelope",
        "text": "Confidential: Alpha-MR-11: Long when price falls below 20D SMA - 3% envelope. Short when price rises above 20D SMA + 3% envelope. ATR-based position sizing.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "mean_reversion",
        "tags": ["mean_reversion", "envelope", "sma"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0067", "title": "Mean Reversion: Correlation Breakdown Trade",
        "text": "Confidential: Alpha-MR-12: When 20D correlation between two historically correlated names (r > 0.8) drops below 0.3, enter convergence trade. Size: 0.8% NAV per leg.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "mean_reversion",
        "tags": ["mean_reversion", "correlation", "convergence"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0068", "title": "Mean Reversion: Z-Score Cross-Sectional",
        "text": "Confidential: Alpha-MR-13: Long bottom-decile z-score (5D return normalized by 60D vol) names. Short top-decile. Rebalance weekly. Hold 5D average.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "mean_reversion",
        "tags": ["mean_reversion", "zscore", "cross-sectional"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0069", "title": "Mean Reversion: Post-Selloff Recovery",
        "text": "Confidential: Alpha-MR-14: Long quality names (quality score > 0.7) after 3D drawdown > 8%. Entry T+1 at open. Hold 10D. Stop at -5% additional drawdown.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "mean_reversion",
        "tags": ["mean_reversion", "recovery", "quality"], "parameter_count": 5, "has_threshold_conditions": True,
    },
    {
        "_id": "S0070", "title": "Mean Reversion: Calendar Spread Normalization",
        "text": "Confidential: Alpha-MR-15: Trade futures calendar spread when backwardation exceeds 2x historical average. Convergence trade with 20D horizon. Cap at 3% portfolio risk.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "mean_reversion",
        "tags": ["mean_reversion", "calendar_spread", "futures"], "parameter_count": 3, "has_threshold_conditions": True,
    },

    # =========================================================================
    # STATISTICAL ARBITRAGE (12 records)
    # =========================================================================
    {
        "_id": "S0071", "title": "StatArb: PCA Residual Alpha",
        "text": "Confidential: Alpha-SA-01: Extract first 5 PCA factors from sector returns. Trade residuals when |z-score| > 2.0. Mean reversion horizon: 3-7D. Max 30 simultaneous positions.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "stat_arb",
        "tags": ["stat_arb", "pca", "residual"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0072", "title": "StatArb: Cointegration Portfolio",
        "text": "Confidential: Alpha-SA-02: Identify cointegrated triplets using Johansen test (p < 0.01). Trade when spread > 2.2 sigma. Lookback: 120D. Rebalance hedge ratios weekly.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "stat_arb",
        "tags": ["stat_arb", "cointegration", "johansen"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0073", "title": "StatArb: Factor Residual Trading",
        "text": "Confidential: Alpha-SA-03: Regress returns on Fama-French 5 factors + momentum. Trade idiosyncratic residuals when cumulative 5D residual > 3%. Dollar-neutral construction.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "stat_arb",
        "tags": ["stat_arb", "factor_residual", "fama_french"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0074", "title": "StatArb: Sector ETF Basis Trade",
        "text": "Confidential: Alpha-SA-04: Trade sector ETF vs constituent basket when tracking error > 50 bps intraday. Market-make the spread. Target 15-25 bps per round trip.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "stat_arb",
        "tags": ["stat_arb", "etf_basis", "tracking_error"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0075", "title": "StatArb: Earnings Season Dispersion",
        "text": "Confidential: Alpha-SA-05: During earnings season, trade single-stock vol vs index vol when implied vol spread > 1.5x historical average. Delta-hedge daily.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "stat_arb",
        "tags": ["stat_arb", "dispersion", "volatility"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0076", "title": "StatArb: Cross-Listed Arbitrage",
        "text": "Confidential: Alpha-SA-06: Trade ADR vs home market when FX-adjusted price differential > 0.4%. Execute via DMA. Account for withholding tax differentials.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "stat_arb",
        "tags": ["stat_arb", "adr", "cross_listed"], "parameter_count": 2, "has_threshold_conditions": True,
    },
    {
        "_id": "S0077", "title": "StatArb: Intraday Lead-Lag",
        "text": "Confidential: Alpha-SA-07: Exploit 5-minute lead-lag between large-cap and mid-cap names in same industry. Signal decays in 15-20 minutes. Max holding: 1 hour.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "stat_arb",
        "tags": ["stat_arb", "lead_lag", "intraday"], "parameter_count": 3, "has_threshold_conditions": False,
    },
    {
        "_id": "S0078", "title": "StatArb: Options-Implied Direction",
        "text": "Confidential: Alpha-SA-08: Trade equity when put-call skew deviates > 2 sigma from 30D rolling mean. Buy equity when skew is abnormally negative (puts expensive). Hold 5D.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "stat_arb",
        "tags": ["stat_arb", "options", "skew"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0079", "title": "StatArb: Index Rebalance Front-Running",
        "text": "Confidential: Alpha-SA-09: Buy anticipated S&P 500 additions 10D before announcement based on market cap / liquidity screens. Sell day after effective date.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "stat_arb",
        "tags": ["stat_arb", "index_rebalance", "front_running"], "parameter_count": 3, "has_threshold_conditions": False,
    },
    {
        "_id": "S0080", "title": "StatArb: Convertible Bond Arbitrage",
        "text": "Confidential: Alpha-SA-10: Long convertible bond, short delta-equivalent equity. Gamma scalp when realized vol > implied. Target 200 bps annualized. Max 2% NAV per position.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "stat_arb",
        "tags": ["stat_arb", "convertible", "gamma"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0081", "title": "StatArb: Machine Learning Signal Ensemble",
        "text": "Confidential: Alpha-SA-11: Ensemble of 5 ML models (ridge, lasso, RF, gradient boost, NN) predicting 5D returns. Trade when ensemble agreement > 80% and predicted |return| > 2%.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "stat_arb",
        "tags": ["stat_arb", "ml", "ensemble"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0082", "title": "StatArb: Microstructure Alpha",
        "text": "Confidential: Alpha-SA-12: Trade on order flow imbalance when bid-side volume / total volume > 0.65 for 10-minute window. Fade when imbalance normalizes. Latency: < 50ms.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "stat_arb",
        "tags": ["stat_arb", "microstructure", "order_flow"], "parameter_count": 3, "has_threshold_conditions": True,
    },

    # =========================================================================
    # VOLATILITY STRATEGIES (12 records)
    # =========================================================================
    {
        "_id": "S0083", "title": "Volatility: Variance Risk Premium",
        "text": "Confidential: Alpha-VOL-01: Systematically sell 30D ATM straddles on S&P 500 when VRP (implied - realized) > 3 vol points. Delta-hedge daily. Size: 5% notional.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "volatility",
        "tags": ["volatility", "vrp", "straddle"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0084", "title": "Volatility: Vol Surface Trading",
        "text": "Confidential: Alpha-VOL-02: Trade butterfly spreads when 25-delta skew > 2 sigma from 90D mean. Buy OTM puts, sell ATM, buy OTM calls. Monthly expiry cycle.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "volatility",
        "tags": ["volatility", "skew", "butterfly"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0085", "title": "Volatility: Dispersion Trading",
        "text": "Confidential: Alpha-VOL-03: Sell index vol, buy single-stock vol when implied correlation > 75th percentile historically. Target 20 names per basket. Monthly roll.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "volatility",
        "tags": ["volatility", "dispersion", "correlation"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0086", "title": "Volatility: VIX Futures Carry",
        "text": "Confidential: Alpha-VOL-04: Short VIX front-month futures when term structure contango > 5%. Roll at T-7. Hard stop: VIX spot > 30. Max allocation: 8% portfolio.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "volatility",
        "tags": ["volatility", "vix_futures", "carry"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0087", "title": "Volatility: Realized Vol Breakout",
        "text": "Confidential: Alpha-VOL-05: Buy straddles when 5D realized vol < 10th percentile of 1Y distribution. Expect vol expansion. Hold to 50% of max premium or 10D.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "volatility",
        "tags": ["volatility", "breakout", "straddle"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0088", "title": "Volatility: Earnings Vol Trading",
        "text": "Confidential: Alpha-VOL-06: Sell strangles 5D before earnings when implied move > 1.5x historical average move. Buy back day after earnings. Size: 0.3% NAV per trade.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "volatility",
        "tags": ["volatility", "earnings", "strangle"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0089", "title": "Volatility: Tail Risk Hedging",
        "text": "Confidential: Alpha-VOL-07: Maintain 2% portfolio allocation to 10-delta S&P puts, 90D expiry. Roll monthly. Increase to 4% when credit spreads widen > 50 bps in 5D.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "volatility",
        "tags": ["volatility", "tail_risk", "hedging"], "parameter_count": 5, "has_threshold_conditions": True,
    },
    {
        "_id": "S0090", "title": "Volatility: Cross-Asset Vol Arbitrage",
        "text": "Confidential: Alpha-VOL-08: Trade equity vol vs FX vol when ratio deviates > 1.5 sigma from 6M mean. Use vega-neutral construction. Max holding: 30D.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "volatility",
        "tags": ["volatility", "cross_asset", "arbitrage"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0091", "title": "Volatility: Gamma Scalping System",
        "text": "Confidential: Alpha-VOL-09: Buy 30D ATM options when implied vol < 20th percentile. Delta-hedge every 0.5% move in underlying. Target: realized vol > implied by 2+ points.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "volatility",
        "tags": ["volatility", "gamma", "scalping"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0092", "title": "Volatility: Calendar Spread System",
        "text": "Confidential: Alpha-VOL-10: Sell front-month, buy back-month when term structure steepness > 90th percentile. Vega-neutral. Target 3-5% return per cycle.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "volatility",
        "tags": ["volatility", "calendar_spread", "term_structure"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0093", "title": "Volatility: Skew Normalization Trade",
        "text": "Confidential: Alpha-VOL-11: When put skew (25D - ATM IV) > 8 vol points, sell risk reversals (sell put, buy call). Close when skew normalizes to < 4 points.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "volatility",
        "tags": ["volatility", "skew", "risk_reversal"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0094", "title": "Volatility: Vol Regime Classification",
        "text": "Confidential: Alpha-VOL-12: Classify regime using HMM on realized vol: low (<12%), normal (12-20%), high (>20%). Switch strategy allocation based on regime. Transition detection lag: 3D.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "volatility",
        "tags": ["volatility", "regime", "hmm"], "parameter_count": 4, "has_threshold_conditions": True,
    },

    # =========================================================================
    # MACRO / GLOBAL (10 records)
    # =========================================================================
    {
        "_id": "S0095", "title": "Macro: FX Carry Trade",
        "text": "Confidential: Alpha-MAC-01: Long top-3 G10 carry currencies, short bottom-3. Rebalance monthly. Position size: 2% NAV per pair. Stop: -4% monthly drawdown triggers pause.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "macro",
        "tags": ["macro", "fx", "carry"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0096", "title": "Macro: Trend Following CTA",
        "text": "Confidential: Alpha-MAC-02: Trade 12 futures markets (4 equity, 4 bond, 4 commodity). Long/short based on 12M vs 1M price. Risk parity weighting. Target 10% vol.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "macro",
        "tags": ["macro", "trend", "cta"], "parameter_count": 4, "has_threshold_conditions": False,
    },
    {
        "_id": "S0097", "title": "Macro: Risk Parity Allocation",
        "text": "Confidential: Alpha-MAC-03: Allocate across equity, bonds, commodities, gold using inverse-vol weighting. Target 8% portfolio vol. Rebalance when any asset drifts > 2% from target.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "macro",
        "tags": ["macro", "risk_parity", "allocation"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0098", "title": "Macro: Yield Curve Steepener",
        "text": "Confidential: Alpha-MAC-04: Enter 2s10s steepener when spread < 20 bps. Target: 80 bps. DV01-neutral. Max duration risk: 50 bps P&L per 1 bps curve move.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "macro",
        "tags": ["macro", "yield_curve", "steepener"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0099", "title": "Macro: Commodity Momentum",
        "text": "Confidential: Alpha-MAC-05: Long top-3 commodities by 12M return, short bottom-3. Universe: 24 liquid futures. Roll at T-5. Rebalance monthly. Max 2% NAV per contract.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "macro",
        "tags": ["macro", "commodity", "momentum"], "parameter_count": 4, "has_threshold_conditions": False,
    },
    {
        "_id": "S0100", "title": "Macro: EM Sovereign Spread",
        "text": "Confidential: Alpha-MAC-06: Long EM sovereign bonds when spread over US Treasury > 400 bps and narrowing. Short when spread < 200 bps and widening. Hold 30-60D.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "macro",
        "tags": ["macro", "em", "sovereign"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0101", "title": "Macro: Inflation Breakeven Trade",
        "text": "Confidential: Alpha-MAC-07: Long TIPS, short nominal Treasuries when 5Y breakeven < 1.8%. Close when breakeven > 2.5%. Duration-matched. Max 5% NAV.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "macro",
        "tags": ["macro", "inflation", "tips"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0102", "title": "Macro: Cross-Asset Momentum",
        "text": "Confidential: Alpha-MAC-08: Apply time-series momentum to 40 assets across 5 classes. Signal: 12M return sign. Risk target: 1% per asset. Rebalance monthly.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "macro",
        "tags": ["macro", "cross_asset", "tsmom"], "parameter_count": 3, "has_threshold_conditions": False,
    },
    {
        "_id": "S0103", "title": "Macro: Central Bank Watch",
        "text": "Confidential: Alpha-MAC-09: Position for rate decisions: long duration 5D before expected cut (OIS implied > 70% probability). Short duration before expected hike. Size: 3% NAV.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "macro",
        "tags": ["macro", "central_bank", "rates"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0104", "title": "Macro: Gold-Equity Hedge Ratio",
        "text": "Confidential: Alpha-MAC-10: Maintain dynamic gold hedge: 8% allocation baseline, increase to 15% when equity-gold 60D correlation drops below -0.3. Rebalance weekly.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "macro",
        "tags": ["macro", "gold", "hedging"], "parameter_count": 4, "has_threshold_conditions": True,
    },

    # =========================================================================
    # EVENT-DRIVEN (12 records)
    # =========================================================================
    {
        "_id": "S0105", "title": "Event: Post-Earnings Drift v2",
        "text": "Confidential: Alpha-EVT-01: Long after earnings beat > 2 sigma (standardized unexpected earnings). Entry T+1. Hold 60D. Only top-200 liquid names. Cap 1.5% NAV.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "event_driven",
        "tags": ["event", "earnings", "sue"], "parameter_count": 5, "has_threshold_conditions": True,
    },
    {
        "_id": "S0106", "title": "Event: M&A Spread Arbitrage",
        "text": "Confidential: Alpha-EVT-02: Buy target at 2-5% discount to deal price on announced cash deals. Require regulatory probability > 85%. Hold to close. Max 3% NAV per deal.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "event_driven",
        "tags": ["event", "merger", "arbitrage"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0107", "title": "Event: Buyback Announcement",
        "text": "Confidential: Alpha-EVT-03: Long on buyback announcement if program > 5% of market cap and company has positive FCF yield. Hold 30D. Historical alpha: +3% average.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "event_driven",
        "tags": ["event", "buyback", "announcement"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0108", "title": "Event: Spin-Off Value Capture",
        "text": "Confidential: Alpha-EVT-04: Buy parent company pre-spinoff when SpinCo expected market cap < $5B (forced selling by index funds). Hold SpinCo for 90D post-separation.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "event_driven",
        "tags": ["event", "spinoff", "value"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0109", "title": "Event: Insider Purchase Cluster",
        "text": "Confidential: Alpha-EVT-05: Long when >= 3 distinct insiders buy within 10D window AND total purchase > $500K. Hold 45D. Filter: exclude scheduled 10b5-1 plans.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "event_driven",
        "tags": ["event", "insider", "cluster"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0110", "title": "Event: Dividend Initiation",
        "text": "Confidential: Alpha-EVT-06: Long on first-ever dividend initiation if yield > 1.5% and payout ratio < 40%. Hold 60D. Historical win rate: 68%. Cap 1.0% NAV.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "event_driven",
        "tags": ["event", "dividend", "initiation"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0111", "title": "Event: FDA Approval Binary",
        "text": "Confidential: Alpha-EVT-07: Buy straddles on Phase 3 readout candidates 10D before PDUFA date. Size: 0.2% NAV. Target 3x premium on binary outcome. Max loss: premium paid.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "event_driven",
        "tags": ["event", "fda", "biotech"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0112", "title": "Event: Activist 13D Filing",
        "text": "Confidential: Alpha-EVT-08: Long within 2D of 13D filing by known activist (top-20 by AUM). Hold 90D or until proxy resolution. Filter: target must be below 15x P/E.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "event_driven",
        "tags": ["event", "activist", "13d"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0113", "title": "Event: Index Addition Anticipation",
        "text": "Confidential: Alpha-EVT-09: Buy anticipated Russell 1000 additions 15D before reconstitution. Criteria: market cap rank 950-1050, positive momentum. Sell reconstitution day.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "event_driven",
        "tags": ["event", "index", "russell"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0114", "title": "Event: Management Change Alpha",
        "text": "Confidential: Alpha-EVT-10: Long when new CEO appointed from outside AND company has negative 12M return > -20%. Hold 180D. Historical alpha: +8% median.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "event_driven",
        "tags": ["event", "management", "ceo"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0115", "title": "Event: Earnings Guidance Withdrawal",
        "text": "Confidential: Alpha-EVT-11: Short when company withdraws forward guidance unexpectedly. Entry same day. Hold 20D. Size: 0.8% NAV. Stop: +5% against position.",
        "sensitivity_level": 3, "category": "strategy_logic", "strategy_archetype": "event_driven",
        "tags": ["event", "guidance", "withdrawal"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0116", "title": "Event: Secondary Offering Discount",
        "text": "Confidential: Alpha-EVT-12: Buy at secondary offering price when discount > 5% to prior close. Sell T+5. Require deal size < 10% of float. Win rate: ~72%.",
        "sensitivity_level": 2, "category": "strategy_logic", "strategy_archetype": "event_driven",
        "tags": ["event", "secondary", "offering"], "parameter_count": 4, "has_threshold_conditions": True,
    },

    # =========================================================================
    # RISK MODELS (18 records)
    # =========================================================================
    {
        "_id": "S0117", "title": "Risk: VaR Methodology v3",
        "text": "Confidential: Use parametric VaR at 99% confidence with 252D lookback. Overlay Monte Carlo VaR with 10,000 simulations for tail risk. Report both daily.",
        "sensitivity_level": 2, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "var", "methodology"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0118", "title": "Risk: Stress Test Scenarios v2",
        "text": "Confidential: Stress test scenarios: 2008-GFC (equity -40%, credit +300bps), 2020-COVID (equity -35%, vol +200%), Rates Shock (duration +200bps). Run weekly.",
        "sensitivity_level": 2, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "stress_test", "scenarios"], "parameter_count": 6, "has_threshold_conditions": True,
    },
    {
        "_id": "S0119", "title": "Risk: Correlation Matrix Update",
        "text": "Confidential: Update correlation matrix using exponential decay (half-life 60D). Override with DCC-GARCH during regime changes. Cap pairwise correlation at 0.95.",
        "sensitivity_level": 2, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "correlation", "garch"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0120", "title": "Risk: Drawdown Recovery Protocol",
        "text": "Confidential: At -4% drawdown: reduce gross by 20%. At -6%: reduce by 40% and block new adds. At -8%: notify CRO and implement full risk-off. Recovery: gradual over 10D.",
        "sensitivity_level": 3, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "drawdown", "protocol"], "parameter_count": 5, "has_threshold_conditions": True,
    },
    {
        "_id": "S0121", "title": "Risk: Sector Concentration Limits v2",
        "text": "Confidential: Max sector exposure: 25% for tech, 20% for financials, 15% for all others. Measure at both long and short book levels. Alert at 90% of limit.",
        "sensitivity_level": 2, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "sector", "concentration"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0122", "title": "Risk: Beta Hedging Parameters",
        "text": "Confidential: Target portfolio beta: 0.0 +/- 0.1. Hedge using ES futures. Update beta estimate daily using 60D OLS. Rebalance hedge when beta drifts > 0.15.",
        "sensitivity_level": 3, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "beta", "hedging"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0123", "title": "Risk: Counterparty Exposure Limits",
        "text": "Confidential: Max counterparty exposure: 15% of NAV for prime brokers, 5% for OTC derivatives, 3% for repo. Daily reconciliation required. Breach = immediate CRO escalation.",
        "sensitivity_level": 2, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "counterparty", "limits"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0124", "title": "Risk: Tail Risk Budget",
        "text": "Confidential: Allocate 1.5% of NAV annually to tail hedges. Split: 60% put spreads, 40% VIX calls. Increase to 3% when regime indicator signals 'high risk'.",
        "sensitivity_level": 2, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "tail", "budget"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0125", "title": "Risk: Liquidity Risk Scoring",
        "text": "Confidential: Score each position 1-5 based on: ADV, bid-ask spread, market cap. Require portfolio-weighted liquidity score > 3.5. Liquidation horizon: 95% within 3D.",
        "sensitivity_level": 2, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "liquidity", "scoring"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0126", "title": "Risk: Factor Exposure Bands",
        "text": "Confidential: Target factor exposures: Market [-0.1, 0.1], Size [-0.2, 0.2], Value [-0.3, 0.3], Momentum [-0.2, 0.2]. Rebalance when any band breached by > 50%.",
        "sensitivity_level": 3, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "factor", "exposure"], "parameter_count": 5, "has_threshold_conditions": True,
    },
    {
        "_id": "S0127", "title": "Risk: Margin Utilization Protocol",
        "text": "Confidential: Target margin utilization: 60-70% of available. Alert at 80%. Hard stop at 90%: auto-reduce positions starting with lowest alpha. Report to CFO daily.",
        "sensitivity_level": 2, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "margin", "utilization"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0128", "title": "Risk: P&L Attribution Model",
        "text": "Confidential: Decompose daily P&L into: alpha (idiosyncratic), factor (systematic), trading costs, financing costs. Use Brinson-style attribution for sector allocation decisions.",
        "sensitivity_level": 1, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "pnl", "attribution"], "parameter_count": 0, "has_threshold_conditions": False,
    },
    {
        "_id": "S0129", "title": "Risk: Concentration Risk Monitor",
        "text": "Confidential: Herfindahl index of position sizes must be < 0.08. Top-5 positions must be < 30% of gross. Track daily and flag intraday if trade would breach.",
        "sensitivity_level": 2, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "concentration", "herfindahl"], "parameter_count": 2, "has_threshold_conditions": True,
    },
    {
        "_id": "S0130", "title": "Risk: Currency Hedging Framework",
        "text": "Confidential: Hedge 80% of developed market FX exposure, 50% of EM FX. Use 1M forwards, roll at T-2. Unhedged portion: max 5% of NAV in any single currency.",
        "sensitivity_level": 2, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "currency", "hedging"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0131", "title": "Risk: Intraday Risk Limits",
        "text": "Confidential: Intraday loss limit: -1.5% NAV triggers auto-flatten new positions. -2.5% triggers full risk-off. Trader must acknowledge and CRO notified within 15 minutes.",
        "sensitivity_level": 3, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "intraday", "limits"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0132", "title": "Risk: Model Validation Schedule",
        "text": "Confidential: All pricing models validated quarterly by independent risk team. VaR backtesting monthly (Kupiec test, p < 0.05 = fail). Factor model R-squared must exceed 0.65.",
        "sensitivity_level": 1, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "validation", "backtesting"], "parameter_count": 2, "has_threshold_conditions": True,
    },
    {
        "_id": "S0133", "title": "Risk: Leverage Limits by Strategy",
        "text": "Confidential: Gross leverage limits: momentum 2.0x, mean reversion 1.5x, stat arb 3.0x, macro 1.0x. Net leverage: -0.2x to +0.3x across all strategies combined.",
        "sensitivity_level": 3, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "leverage", "limits"], "parameter_count": 5, "has_threshold_conditions": True,
    },
    {
        "_id": "S0134", "title": "Risk: ESG Exclusion List",
        "text": "Confidential: Exclude companies with ESG score < 20 (MSCI scale), controversial weapons involvement, or thermal coal revenue > 30%. Review quarterly. Override requires IC approval.",
        "sensitivity_level": 1, "category": "risk_model", "strategy_archetype": "risk_model",
        "tags": ["risk", "esg", "exclusion"], "parameter_count": 2, "has_threshold_conditions": True,
    },

    # =========================================================================
    # EXECUTION / PORTFOLIO (18 records)
    # =========================================================================
    {
        "_id": "S0135", "title": "Execution: Optimal Execution VWAP v2",
        "text": "Confidential: VWAP benchmark: split order into 5-minute buckets weighted by historical volume profile. Urgency parameter alpha = 0.3 for alpha-driven, 0.1 for rebalance.",
        "sensitivity_level": 2, "category": "execution_policy", "strategy_archetype": "execution",
        "tags": ["execution", "vwap", "benchmark"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0136", "title": "Execution: Market Impact Model v2",
        "text": "Confidential: Impact model: I = k * sigma * sqrt(Q/V) where k=0.314 for large-cap, k=0.52 for mid-cap, k=0.81 for small-cap. Sigma = 20D realized vol. V = 20D ADV.",
        "sensitivity_level": 3, "category": "execution_policy", "strategy_archetype": "execution",
        "tags": ["execution", "impact", "model"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0137", "title": "Execution: Smart Order Router Config",
        "text": "Confidential: SOR priority: lit venues first if spread < 2 bps, dark pools for orders > 5% ADV, midpoint pegging for passive fills. Max 3 venues simultaneously.",
        "sensitivity_level": 2, "category": "execution_policy", "strategy_archetype": "execution",
        "tags": ["execution", "sor", "routing"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0138", "title": "Execution: Implementation Shortfall Target",
        "text": "Confidential: Target IS < 15 bps for large-cap, < 25 bps for mid-cap, < 40 bps for small-cap. Review monthly. Traders exceeding targets for 3 consecutive months flagged for review.",
        "sensitivity_level": 2, "category": "execution_policy", "strategy_archetype": "execution",
        "tags": ["execution", "implementation_shortfall", "target"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0139", "title": "Execution: Pre-Trade TCA Thresholds",
        "text": "Confidential: Pre-trade TCA required for orders > 10% ADV or > $5M notional. If estimated impact > 30 bps, escalate to PM for approval. Log all overrides.",
        "sensitivity_level": 2, "category": "execution_policy", "strategy_archetype": "execution",
        "tags": ["execution", "tca", "pre_trade"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0140", "title": "Execution: Auction Strategy Rules",
        "text": "Confidential: Closing auction: participate for rebalance trades only when residual > 20% of target fill. Opening auction: never participate for momentum trades (information leakage risk).",
        "sensitivity_level": 2, "category": "execution_policy", "strategy_archetype": "execution",
        "tags": ["execution", "auction", "strategy"], "parameter_count": 2, "has_threshold_conditions": True,
    },
    {
        "_id": "S0141", "title": "Execution: Cross-Border Settlement Rules",
        "text": "Confidential: Pre-fund all EM trades T-1. DM trades: T+1 settlement assumed. FX hedges must be placed within 30 minutes of equity trade confirmation.",
        "sensitivity_level": 1, "category": "execution_policy", "strategy_archetype": "execution",
        "tags": ["execution", "settlement", "cross_border"], "parameter_count": 2, "has_threshold_conditions": False,
    },
    {
        "_id": "S0142", "title": "Portfolio: Rebalance Optimization",
        "text": "Confidential: Rebalance optimizer minimizes turnover subject to: max tracking error 50 bps from target, max single trade 15% of position. Use quadratic programming solver.",
        "sensitivity_level": 2, "category": "portfolio_policy", "strategy_archetype": "execution",
        "tags": ["portfolio", "rebalance", "optimization"], "parameter_count": 2, "has_threshold_conditions": True,
    },
    {
        "_id": "S0143", "title": "Portfolio: Cash Management Policy",
        "text": "Confidential: Maintain 2-4% cash buffer. Invest excess in overnight repo. If cash > 5%, deploy into short-duration Treasuries within 2 business days.",
        "sensitivity_level": 1, "category": "portfolio_policy", "strategy_archetype": "execution",
        "tags": ["portfolio", "cash", "management"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0144", "title": "Portfolio: Tax-Loss Harvesting Rules",
        "text": "Confidential: Harvest losses when position down > 5% and holding period > 31 days. Replace with correlated substitute (r > 0.9). Wash sale buffer: 31 calendar days.",
        "sensitivity_level": 1, "category": "portfolio_policy", "strategy_archetype": "execution",
        "tags": ["portfolio", "tax", "harvesting"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0145", "title": "Portfolio: Turnover Budget Allocation",
        "text": "Confidential: Annual turnover budget: 800% (gross). Allocate: 60% alpha signals, 25% rebalance, 15% risk management. Monthly tracking vs budget. Excess requires CIO approval.",
        "sensitivity_level": 2, "category": "portfolio_policy", "strategy_archetype": "execution",
        "tags": ["portfolio", "turnover", "budget"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0146", "title": "Portfolio: Position Sizing Framework",
        "text": "Confidential: Base position size = alpha_score * vol_adjustment * liquidity_score. Max: 3% NAV. Min: 0.3% NAV. Vol adjustment = target_vol / position_vol.",
        "sensitivity_level": 3, "category": "portfolio_policy", "strategy_archetype": "execution",
        "tags": ["portfolio", "sizing", "framework"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0147", "title": "Execution: Algo Selection Matrix",
        "text": "Confidential: Urgent alpha trades: arrival price algo. Rebalance: VWAP. Liquidation: TWAP over 3D. Large blocks (>20% ADV): negotiate via block desk or dark crossing.",
        "sensitivity_level": 2, "category": "execution_policy", "strategy_archetype": "execution",
        "tags": ["execution", "algo", "selection"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0148", "title": "Execution: Broker Allocation Policy",
        "text": "Confidential: Top-5 brokers receive 70% of flow based on research + execution quality scores. Rotate quarterly. Minimum 3 brokers per asset class for best execution compliance.",
        "sensitivity_level": 1, "category": "execution_policy", "strategy_archetype": "execution",
        "tags": ["execution", "broker", "allocation"], "parameter_count": 2, "has_threshold_conditions": True,
    },
    {
        "_id": "S0149", "title": "Portfolio: NAV Calculation Method",
        "text": "Confidential: Official NAV at 4:00 PM ET using last traded price. Illiquid positions: use bid-side mark. Adjustments for pending corporate actions applied T+0. Reconcile vs admin daily.",
        "sensitivity_level": 1, "category": "portfolio_policy", "strategy_archetype": "execution",
        "tags": ["portfolio", "nav", "calculation"], "parameter_count": 0, "has_threshold_conditions": False,
    },
    {
        "_id": "S0150", "title": "Execution: Error Handling Protocol",
        "text": "Confidential: Trade errors: notify PM + compliance within 15 minutes. Errors > $100K: escalate to CRO. Maintain error account. P&L attribution: errors excluded from track record.",
        "sensitivity_level": 1, "category": "execution_policy", "strategy_archetype": "execution",
        "tags": ["execution", "error", "protocol"], "parameter_count": 1, "has_threshold_conditions": True,
    },
    {
        "_id": "S0151", "title": "Portfolio: Benchmark Tracking Framework",
        "text": "Confidential: Track vs S&P 500 for US equity, MSCI EAFE for international. Active share target: 70-85%. Information ratio target: > 1.0 rolling 12M.",
        "sensitivity_level": 2, "category": "portfolio_policy", "strategy_archetype": "execution",
        "tags": ["portfolio", "benchmark", "tracking"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0152", "title": "Execution: FIX Protocol Configuration",
        "text": "Confidential: FIX 4.4 for all equity venues. Heartbeat interval: 30s. Max order rate: 50/second per session. Cancel-on-disconnect enabled. Session keys rotated monthly.",
        "sensitivity_level": 2, "category": "execution_policy", "strategy_archetype": "execution",
        "tags": ["execution", "fix", "protocol"], "parameter_count": 3, "has_threshold_conditions": True,
    },

    # =========================================================================
    # COMMITTEE / CLIENT (12 records)
    # =========================================================================
    {
        "_id": "S0153", "title": "Committee: Investment Committee Charter",
        "text": "Confidential: IC meets weekly. Quorum: 3 of 5 members. New strategy approval requires unanimous vote. Position limit changes require 4 of 5. Minutes retained 7 years.",
        "sensitivity_level": 1, "category": "committee_notes", "strategy_archetype": "committee",
        "tags": ["committee", "charter", "governance"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0154", "title": "Committee: Strategy Sunset Policy",
        "text": "Confidential: Any strategy underperforming by > 3% annualized vs benchmark for 18 consecutive months triggers sunset review. Strategies with < $50M allocation also reviewed.",
        "sensitivity_level": 1, "category": "committee_notes", "strategy_archetype": "committee",
        "tags": ["committee", "sunset", "review"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0155", "title": "Client: Pension Fund Mandate Constraints",
        "text": "Confidential: Client-B (pension): no leverage, max 5% single name, no derivatives except hedging, ESG exclusion list applies. Quarterly reporting with attribution.",
        "sensitivity_level": 2, "category": "client_sensitive", "strategy_archetype": "committee",
        "tags": ["client", "pension", "mandate"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0156", "title": "Client: Endowment Mandate Terms",
        "text": "Confidential: Client-C (endowment): max 1.5x gross leverage, 30% max non-US, $10M minimum trade size. Performance fee: 15% over 6% hurdle, annual crystallization.",
        "sensitivity_level": 2, "category": "client_sensitive", "strategy_archetype": "committee",
        "tags": ["client", "endowment", "terms"], "parameter_count": 5, "has_threshold_conditions": True,
    },
    {
        "_id": "S0157", "title": "Client: Family Office Custom SMA",
        "text": "Confidential: Client-D (family office): $25M SMA, concentrated 20-position portfolio, no shorts, exclude tobacco/gambling. Monthly calls, quarterly in-person review.",
        "sensitivity_level": 2, "category": "client_sensitive", "strategy_archetype": "committee",
        "tags": ["client", "family_office", "sma"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0158", "title": "Committee: Risk Budget Allocation FY2025",
        "text": "Confidential: FY2025 risk budget: momentum 35%, mean reversion 25%, stat arb 20%, macro 15%, event 5%. Total target vol: 8% annualized. Reviewed semi-annually.",
        "sensitivity_level": 3, "category": "committee_notes", "strategy_archetype": "committee",
        "tags": ["committee", "budget", "allocation"], "parameter_count": 6, "has_threshold_conditions": True,
    },
    {
        "_id": "S0159", "title": "Committee: Compensation Structure",
        "text": "Confidential: PM comp: base + 15-25% of strategy P&L above high-water mark. Clawback: 3-year vesting. Deferred comp in fund units. Cap: $5M annual total.",
        "sensitivity_level": 3, "category": "committee_notes", "strategy_archetype": "committee",
        "tags": ["committee", "compensation", "structure"], "parameter_count": 4, "has_threshold_conditions": True,
    },
    {
        "_id": "S0160", "title": "Committee: Compliance Review Findings Q4",
        "text": "Confidential: Q4 findings: 2 pre-trade limit breaches (resolved same day), 1 late trade report (15-minute SLA missed). No material violations. Next review: March.",
        "sensitivity_level": 1, "category": "committee_notes", "strategy_archetype": "committee",
        "tags": ["committee", "compliance", "findings"], "parameter_count": 2, "has_threshold_conditions": True,
    },
    {
        "_id": "S0161", "title": "Client: Sovereign Wealth Fund Requirements",
        "text": "Confidential: Client-E (SWF): min $200M allocation, separate legal entity required, Shariah-compliant screen, quarterly board reporting. No co-investment rights.",
        "sensitivity_level": 2, "category": "client_sensitive", "strategy_archetype": "committee",
        "tags": ["client", "swf", "requirements"], "parameter_count": 3, "has_threshold_conditions": False,
    },
    {
        "_id": "S0162", "title": "Committee: Technology Stack Decision",
        "text": "Confidential: Approved tech stack: Python/C++ for alpha, kdb+ for tick data, Bloomberg API for market data, internal OMS built on FIX 4.4. Cloud: AWS us-east-1 only.",
        "sensitivity_level": 1, "category": "committee_notes", "strategy_archetype": "committee",
        "tags": ["committee", "technology", "stack"], "parameter_count": 0, "has_threshold_conditions": False,
    },
    {
        "_id": "S0163", "title": "Client: Insurance Company Guidelines",
        "text": "Confidential: Client-F (insurance): max duration 5Y, investment-grade only for fixed income, equity beta < 0.8, no commodities. SAP accounting constraints apply.",
        "sensitivity_level": 2, "category": "client_sensitive", "strategy_archetype": "committee",
        "tags": ["client", "insurance", "guidelines"], "parameter_count": 3, "has_threshold_conditions": True,
    },
    {
        "_id": "S0164", "title": "Committee: Disaster Recovery Plan",
        "text": "Confidential: DR site: NJ-2 facility. RTO: 4 hours. RPO: 15 minutes. Full portfolio replication via AWS multi-AZ. Manual override procedures for all automated systems.",
        "sensitivity_level": 1, "category": "committee_notes", "strategy_archetype": "committee",
        "tags": ["committee", "dr", "continuity"], "parameter_count": 2, "has_threshold_conditions": True,
    },
]


def _add_defaults(record: dict) -> dict:
    record.setdefault("source_type", "internal")
    record.setdefault("trust_score", 1.0)
    record.setdefault("sensitivity_level", 3)
    record.setdefault("parameter_count", 0)
    record.setdefault("has_threshold_conditions", False)
    record.setdefault("strategy_archetype", "unknown")
    return record


def load_existing(path: str):
    records = []
    if not os.path.exists(path):
        return records
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def main():
    ap = argparse.ArgumentParser(description="Generate expanded secret corpus for SentinelFlow")
    ap.add_argument("--output", default="data/secrets/secrets.jsonl", type=str)
    ap.add_argument("--mode", choices=["append", "overwrite"], default="append",
                     help="append: add new secrets after existing; overwrite: replace entire file")
    ap.add_argument("--dry_run", action="store_true", help="Print stats without writing")
    args = ap.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    existing = load_existing(str(output_path)) if args.mode == "append" else []
    existing_ids = {r.get("_id") for r in existing}

    new_records = []
    for rec in GENERATED_SECRETS:
        rec = _add_defaults(rec)
        if rec["_id"] not in existing_ids:
            new_records.append(rec)

    print(f"Existing records: {len(existing)}")
    print(f"New records to add: {len(new_records)}")
    print(f"Total after write: {len(existing) + len(new_records)}")

    # Stats
    archetypes = {}
    levels = {1: 0, 2: 0, 3: 0}
    for r in (existing + new_records):
        arch = r.get("strategy_archetype", "unknown")
        archetypes[arch] = archetypes.get(arch, 0) + 1
        lev = r.get("sensitivity_level", 3)
        levels[lev] = levels.get(lev, 0) + 1

    print("\nArchetype distribution:")
    for arch, count in sorted(archetypes.items(), key=lambda x: -x[1]):
        print(f"  {arch}: {count}")

    print(f"\nSensitivity levels: L1={levels[1]}, L2={levels[2]}, L3={levels[3]}")

    if args.dry_run:
        print("\n[DRY RUN] No file written.")
        return

    if args.mode == "overwrite":
        with open(str(output_path), "w", encoding="utf-8") as f:
            for rec in existing:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            for rec in new_records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    else:
        with open(str(output_path), "a", encoding="utf-8") as f:
            for rec in new_records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"\nWritten to: {output_path}")
    print("Next step: rebuild FAISS index with:")
    print("  python scripts/build_secret_faiss_index.py")


if __name__ == "__main__":
    main()
