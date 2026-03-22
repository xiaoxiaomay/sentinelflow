"""
Phase 16b: Generate institutional-grade secrets v2 dataset.
Backup approach: hardcoded high-quality secrets (no API dependency).
Generates 90 secrets (30 L3 + 30 L2 + 30 L1) across 6 alpha domains.
"""
import json
import os

# ── Domain 1: Price/Volume Momentum (5 groups) ──────────────────────────────

DOMAIN_1 = [
    {
        "group_id": 1,
        "domain": "price_volume_momentum",
        "L3": {
            "title": "Momentum Entry: RSI + Volume + Trend",
            "text": "Momentum entry: 14D RSI < 25 AND 5D volume > 2.2x 90D ADTV AND price above 200D EMA, initial position 1.2% NAV; scale-in to max 2.5% if RSI confirms < 20 on Day+3; hard stop at -4.5% from entry; exclude earnings window ±3 days; Universe: Russell 1000 ex-Financials, min $500M mktcap, min $5M ADTV. Momentum sleeve only. Rebalance signal checked at 15:45 ET daily.",
            "notes": "Complete parameter set: RSI thresholds, volume multiplier, position sizing, stop-loss, universe filters"
        },
        "L2": {
            "title": "RSI-Based Momentum Framework",
            "text": "Our desk uses RSI-based momentum signals combined with volume confirmation and trend filters, with staged position sizing and strict stop-loss discipline. Universe restricted to large-cap liquid names excluding event windows.",
            "notes": ""
        },
        "L1": {
            "title": "RSI Momentum Basics",
            "text": "RSI below 30 is commonly interpreted as an oversold signal suggesting potential mean reversion or momentum entry opportunities. Volume confirmation strengthens signal reliability.",
            "notes": ""
        }
    },
    {
        "group_id": 2,
        "domain": "price_volume_momentum",
        "L3": {
            "title": "Breakout Momentum: Bollinger + OBV",
            "text": "Breakout momentum: price closes above 2.0 std Bollinger Band (20D) AND OBV 10D slope > 0.15 AND ADX(14) > 28; entry at next open, position 0.8% NAV; add 0.4% if price holds above band for 2 consecutive closes; trailing stop at 1.5 ATR(14) below highest close; max hold 15 trading days; Universe: S&P 500 ex-Utilities, min $1B mktcap; no entry if VIX > 30. Weekly signal refresh Friday 16:00 ET.",
            "notes": "Bollinger breakout with ADX trend strength filter, OBV confirmation, VIX regime filter"
        },
        "L2": {
            "title": "Volatility Breakout System",
            "text": "We employ a volatility breakout system using Bollinger Bands with trend strength and volume flow confirmation. Position scaling follows breakout persistence, with ATR-based trailing stops and regime-dependent entry gates.",
            "notes": ""
        },
        "L1": {
            "title": "Bollinger Band Breakouts",
            "text": "Bollinger Bands measure price volatility using standard deviations around a moving average. Breakouts above the upper band can signal strong upward momentum continuation.",
            "notes": ""
        }
    },
    {
        "group_id": 3,
        "domain": "price_volume_momentum",
        "L3": {
            "title": "Cross-Sectional Momentum Rank",
            "text": "Cross-sectional momentum: rank stocks by 12M-1M return (skip most recent month); go long top decile, short bottom decile; rebalance monthly on last trading day; position weight = 1/N equal-weight within each leg; gross exposure 180% NAV, net exposure target ±5%; turnover cap 35% monthly; apply 0.3% slippage estimate; Universe: Russell 2000, min $200M mktcap, min $2M ADTV; exclude IPOs < 12 months. Max single-name 1.5% NAV.",
            "notes": "Complete long-short momentum with skip-month, exposure targets, turnover budget"
        },
        "L2": {
            "title": "Cross-Sectional Momentum L/S",
            "text": "Our cross-sectional momentum strategy ranks stocks by trailing returns with a skip-month adjustment, constructing long-short portfolios with controlled exposure and turnover constraints. Equal-weight within decile legs.",
            "notes": ""
        },
        "L1": {
            "title": "Cross-Sectional Momentum",
            "text": "Cross-sectional momentum involves buying recent winners and selling recent losers. The skip-month adjustment removes the short-term reversal effect from the signal.",
            "notes": ""
        }
    },
    {
        "group_id": 4,
        "domain": "price_volume_momentum",
        "L3": {
            "title": "VWAP Reversion Intraday",
            "text": "Intraday mean reversion: if stock deviates > 1.8 std from session VWAP by 11:00 ET AND relative volume > 1.5x AND bid-ask spread < 15 bps, enter counter-trend position 0.5% NAV; target VWAP reversion (take profit at 0.5 std from VWAP); stop at 2.5 std deviation; flatten all positions by 15:50 ET; max 8 concurrent positions; Universe: S&P 500 components with options-implied vol < 40%. No entry on FOMC days or triple-witching.",
            "notes": "Intraday VWAP reversion with spread filter, volatility regime, event exclusions"
        },
        "L2": {
            "title": "Intraday VWAP Reversion",
            "text": "Our intraday desk runs a VWAP mean-reversion strategy targeting large deviations from session VWAP with volume and spread filters. All positions flatten before close with strict concurrency limits and event-day exclusions.",
            "notes": ""
        },
        "L1": {
            "title": "VWAP Mean Reversion",
            "text": "VWAP (Volume Weighted Average Price) serves as an intraday fair value estimate. Prices that deviate significantly from VWAP often revert, creating short-term trading opportunities.",
            "notes": ""
        }
    },
    {
        "group_id": 5,
        "domain": "price_volume_momentum",
        "L3": {
            "title": "Sector Rotation Momentum",
            "text": "Sector rotation: rank 11 GICS sectors by 3M momentum z-score (standardized vs trailing 5Y); overweight top 3 sectors by +4% each vs benchmark, underweight bottom 3 by -3% each; rebalance bi-weekly; apply momentum crash filter: if cross-sectional dispersion of sector returns drops below 20th percentile of 2Y history, reduce all tilts by 50%; max single-sector weight 25% of portfolio; transaction cost budget 8 bps per rebalance; benchmark: S&P 500.",
            "notes": "Sector rotation with z-score ranking, crash filter, dispersion-based regime adjustment"
        },
        "L2": {
            "title": "Systematic Sector Rotation",
            "text": "We run a systematic sector rotation strategy using momentum z-scores with historical standardization. Includes a momentum crash filter based on cross-sectional dispersion that dynamically reduces tilts in low-dispersion regimes.",
            "notes": ""
        },
        "L1": {
            "title": "Sector Rotation Investing",
            "text": "Sector rotation strategies shift portfolio weights among industry sectors based on relative momentum, attempting to capture sector-level trends in economic and market cycles.",
            "notes": ""
        }
    },
]

# ── Domain 2: Event Driven (5 groups) ───────────────────────────────────────

DOMAIN_2 = [
    {
        "group_id": 1,
        "domain": "event_driven",
        "L3": {
            "title": "Post-Earnings Drift: EPS Surprise",
            "text": "Post-earnings drift: go long if EPS surprise > +8% AND revenue surprise > +3% AND management raises FY guidance; entry at Day+1 open, position 1.8% NAV; hold for 12 trading days; stop at -3.5% from entry; add 0.6% NAV if Day+2 analyst upgrades ≥ 2; Universe: S&P 500, exclude financials quarter-end; avoid if implied vol rank > 80th percentile pre-earnings; max 6 concurrent earnings positions. Track via internal signal ID EPS_DRIFT_v3.",
            "notes": "Full PEAD strategy with surprise thresholds, guidance condition, analyst upgrade scaling, vol filter"
        },
        "L2": {
            "title": "Post-Earnings Drift Framework",
            "text": "Our event desk trades post-earnings announcement drift using multi-factor surprise scoring that combines EPS, revenue, and guidance changes. Analyst revision flow provides scaling signals. Position sizing adapts to pre-earnings implied volatility regime.",
            "notes": ""
        },
        "L1": {
            "title": "Post-Earnings Drift",
            "text": "Post-earnings announcement drift (PEAD) is a well-documented anomaly where stocks that beat earnings expectations tend to continue outperforming for weeks following the announcement.",
            "notes": ""
        }
    },
    {
        "group_id": 2,
        "domain": "event_driven",
        "L3": {
            "title": "Merger Arb: Spread + Completion",
            "text": "Merger arbitrage: enter when deal spread > 4% annualized AND estimated completion probability (internal model) > 82%; long target at 1.5% NAV, short acquirer at deal-ratio-adjusted hedge; roll hedge delta daily; exit if spread compresses to < 1.2% annualized or regulatory risk score (internal) exceeds 7/10; max 12 concurrent deals; collateral reserve 15% per position for margin; exclude cross-border deals involving China/Russia; max sector concentration 30% of arb book. Use internal DEAL_SCORE_v2 model.",
            "notes": "Merger arb with proprietary completion model, spread thresholds, regulatory risk score"
        },
        "L2": {
            "title": "Systematic Merger Arbitrage",
            "text": "We run systematic merger arbitrage using a proprietary deal completion probability model, entering positions when spreads exceed our threshold and completion confidence is high. Regulatory risk scoring and sector concentration limits manage downside.",
            "notes": ""
        },
        "L1": {
            "title": "Merger Arbitrage Basics",
            "text": "Merger arbitrage involves buying the target company's stock at a discount to the deal price, profiting from spread compression as the deal closes. Risk centers on deal failure.",
            "notes": ""
        }
    },
    {
        "group_id": 3,
        "domain": "event_driven",
        "L3": {
            "title": "Analyst Revision Momentum",
            "text": "Analyst revision momentum: trigger when ≥ 3 analysts revise EPS estimate up by > 5% within 10 trading days AND stock has not yet moved > 2% since first revision; entry at next open, position 1.0% NAV; target +6% from entry or 20 trading days (whichever first); stop at -2.8%; Universe: Russell 1000, min 8 analysts covering; skip if within 5 days of earnings; downgrade signal: exit immediately if any top-5 ranked analyst (by accuracy) downgrades. Weekly scan Friday 17:00 ET.",
            "notes": "Analyst revision clustering with accuracy-weighted downgrade override"
        },
        "L2": {
            "title": "Analyst Revision Clustering",
            "text": "Our strategy detects clustered analyst upward revisions as leading indicators, entering before the full price adjustment. Analyst accuracy rankings weight exit signals, and earnings proximity gates prevent contaminated entries.",
            "notes": ""
        },
        "L1": {
            "title": "Analyst Revision Effects",
            "text": "Changes in analyst earnings estimates often lead to predictable stock price movements. Clustered upward revisions from multiple analysts tend to signal fundamental improvements not yet priced in.",
            "notes": ""
        }
    },
    {
        "group_id": 4,
        "domain": "event_driven",
        "L3": {
            "title": "Activist 13D Filing Strategy",
            "text": "Activist entry: on 13D filing detection (> 5% stake), if activist has > 60% historical win rate (internal database of 2,400+ campaigns) AND target market cap $2B-$20B AND target trades below sector median EV/EBITDA by > 1.5 turns; enter long 1.2% NAV at Day+1 open; add 0.5% if proxy fight announced; target: 18% return or 9 months (whichever first); stop at -12% from entry; hedge with 30% delta sector ETF short; max 5 concurrent activist positions.",
            "notes": "Activist investing with proprietary win-rate database, valuation filter, hedge structure"
        },
        "L2": {
            "title": "Activist Campaign Trading",
            "text": "We trade activist 13D filings using a proprietary database of historical campaign outcomes to filter for high-probability situations. Entry requires valuation discount and strong activist track record, with sector hedge overlay and strict position limits.",
            "notes": ""
        },
        "L1": {
            "title": "Activist Investing Overview",
            "text": "Activist investors acquire significant stakes in undervalued companies and push for changes to unlock value. SEC 13D filings disclose when an investor crosses the 5% ownership threshold with activist intent.",
            "notes": ""
        }
    },
    {
        "group_id": 5,
        "domain": "event_driven",
        "L3": {
            "title": "Spinoff Discount Capture",
            "text": "Corporate spinoff: enter long spun-off entity at Day+5 post-distribution (allow forced selling to clear) if trading below pre-announcement sum-of-parts estimate by > 15% AND spun-off entity EBITDA margin > parent by ≥ 3pp; position 1.4% NAV; target: convergence to SOTP fair value within 6 months; stop at -10%; pair with parent short at 40% hedge ratio if parent trades above 1.2x SOTP; max 4 spinoff positions; Universe: US-listed, spun-off entity mktcap > $1B. Use internal SOTP_MODEL_v4 for valuations.",
            "notes": "Spinoff discount strategy with SOTP model, forced-selling window, parent hedge"
        },
        "L2": {
            "title": "Spinoff Value Capture",
            "text": "We systematically trade corporate spinoffs by entering after the initial forced-selling period, targeting companies trading below our sum-of-parts estimates. Parent company hedges and EBITDA margin filters refine selection.",
            "notes": ""
        },
        "L1": {
            "title": "Spinoff Investing",
            "text": "Corporate spinoffs often create temporary mispricings as index funds and mandate-constrained investors sell the new entity. This forced selling can push prices below fundamental value, creating entry opportunities.",
            "notes": ""
        }
    },
]

# ── Domain 3: Statistical Arbitrage (5 groups) ──────────────────────────────

DOMAIN_3 = [
    {
        "group_id": 1,
        "domain": "statistical_arbitrage",
        "L3": {
            "title": "Cointegrated Pairs: Energy Sector",
            "text": "Pairs trading (energy): select pairs with Engle-Granger cointegration p-value < 0.03 AND Hurst exponent < 0.42 over trailing 252 days; open mean-reversion trade when spread z-score > 2.1 (or < -2.1); close at z = 0.3; stop-loss at z = 3.8 or after 18 trading days; position size: $500K notional per leg, beta-neutral hedge ratio recalculated weekly; Universe: 45 US energy stocks, min $3B mktcap; re-estimate cointegration monthly; max 8 concurrent pairs; suspend if pair correlation drops below 0.65 in rolling 60D window.",
            "notes": "Full pairs strategy with cointegration tests, Hurst filter, z-score thresholds, correlation decay trigger"
        },
        "L2": {
            "title": "Energy Sector Pairs Trading",
            "text": "We run cointegrated pairs trading in the energy sector using statistical tests to identify mean-reverting spread relationships. Entry and exit follow z-score thresholds with beta-neutral hedging and automatic suspension when correlation structure degrades.",
            "notes": ""
        },
        "L1": {
            "title": "Pairs Trading Concept",
            "text": "Pairs trading is a market-neutral strategy that matches a long position with a short position in two correlated securities. When the spread between them deviates from historical norms, traders bet on convergence.",
            "notes": ""
        }
    },
    {
        "group_id": 2,
        "domain": "statistical_arbitrage",
        "L3": {
            "title": "ETF-Stock Basis Arbitrage",
            "text": "ETF basis arb: monitor 15 sector ETFs vs constituent baskets; enter when ETF premium/discount exceeds ±22 bps (after adjusting for creation/redemption costs of 8 bps); trade via ETF vs basket of top-5 weighted constituents (capturing 65%+ of NAV); hold until basis reverts to < 5 bps; max hold 3 trading days; position size $2M per leg; execute via DMA to minimize footprint; pause if market-wide bid-ask spreads widen > 2x normal (stress regime); run between 10:00-15:30 ET only. Internal signal: ETF_BASIS_v2.",
            "notes": "ETF basis arbitrage with cost-adjusted thresholds, stress regime filter, time-of-day restriction"
        },
        "L2": {
            "title": "ETF Basis Trading",
            "text": "We exploit ETF premium/discount dislocations versus underlying constituent baskets, entering when the basis exceeds our cost-adjusted thresholds. Automated regime detection suspends trading during stress periods when spreads widen.",
            "notes": ""
        },
        "L1": {
            "title": "ETF Arbitrage",
            "text": "ETF arbitrage exploits price differences between an ETF and its underlying basket of securities. The creation/redemption mechanism normally keeps ETF prices close to NAV, but temporary dislocations can occur.",
            "notes": ""
        }
    },
    {
        "group_id": 3,
        "domain": "statistical_arbitrage",
        "L3": {
            "title": "Cross-Listed ADR Spread",
            "text": "ADR spread arb: trade US-listed ADRs vs home-market ordinary shares when FX-adjusted spread > 45 bps AND the dislocation is not explained by dividend timing (ex-date ±3 days) or withholding tax differential; enter both legs simultaneously using synchronized DMA; target spread reversion to < 10 bps; stop if spread widens to > 90 bps; max position $1.5M per leg; currency hedge via 1W FX forward at 70% notional; Universe: 30 liquid European/UK ADRs with > $20M daily US volume; run during overlap hours 9:30-11:30 ET only. Reconcile daily with custodian.",
            "notes": "ADR arbitrage with FX hedge, dividend/tax adjustment, overlap-hours-only execution"
        },
        "L2": {
            "title": "ADR Cross-Listing Arbitrage",
            "text": "We trade dislocations between US-listed ADRs and their home-market ordinary shares, adjusting for FX, dividends, and tax differentials. Currency hedging and synchronized execution across time zones manage basis risk.",
            "notes": ""
        },
        "L1": {
            "title": "ADR Arbitrage",
            "text": "American Depositary Receipts (ADRs) represent foreign shares traded on US exchanges. Price differences between ADRs and underlying shares can arise from time zone gaps, FX movements, and liquidity differences.",
            "notes": ""
        }
    },
    {
        "group_id": 4,
        "domain": "statistical_arbitrage",
        "L3": {
            "title": "Intraday Lead-Lag Microstructure",
            "text": "Lead-lag microstructure: exploit 200-800ms information lead of SPY/QQQ ETF price changes on individual stock prices using co-movement regression; trade stocks whose lagged beta to ETF is > 0.7 AND current tick deviates > 0.12% from predicted value; hold 2-15 seconds; target $0.02/share avg profit; max position 5,000 shares; latency requirement < 50μs order-to-fill; co-location at NY5 data center; Universe: top 200 S&P 500 by ADV; model recalibrated every 30 minutes; kill switch if PnL drawdown > $15K intraday.",
            "notes": "HFT lead-lag with latency specs, co-location, intraday drawdown kill switch"
        },
        "L2": {
            "title": "Lead-Lag Microstructure Trading",
            "text": "Our HFT desk exploits the information lead that index ETFs have over individual stock prices at the millisecond level. Co-movement models predict expected stock price adjustments, and deviations trigger rapid mean-reversion trades with strict drawdown controls.",
            "notes": ""
        },
        "L1": {
            "title": "Market Microstructure",
            "text": "Market microstructure studies how information is incorporated into prices at very short time horizons. Index ETFs often reflect new information slightly before individual stocks adjust, creating lead-lag relationships.",
            "notes": ""
        }
    },
    {
        "group_id": 5,
        "domain": "statistical_arbitrage",
        "L3": {
            "title": "Overnight Return Reversal",
            "text": "Overnight reversal: at 15:55 ET, rank S&P 500 stocks by same-day return; short top 5% (strongest gainers) and long bottom 5% (weakest losers) with equal dollar notional $300K per leg; close all positions at 9:35 ET next day; expected reversal alpha 3-8 bps per overnight hold; net exposure target ±2% of book; screen out stocks with next-day earnings, ex-dividend, or FDA events; max gross exposure $6M; borrow cost threshold < 100 bps annualized for shorts; run Mon-Thu nights only (skip Fri). Internal model: OVNIGHT_REV_v5.",
            "notes": "Overnight reversal with precise timing, event screens, borrow cost filter"
        },
        "L2": {
            "title": "Overnight Reversal Strategy",
            "text": "We systematically capture overnight reversal alpha by trading end-of-day winners and losers in opposite directions, holding overnight and closing at next open. Event screening and borrow cost management are critical operational components.",
            "notes": ""
        },
        "L1": {
            "title": "Overnight Return Patterns",
            "text": "Research shows that stocks with extreme intraday returns often partially reverse overnight. This pattern reflects market microstructure effects including inventory management and institutional rebalancing flows.",
            "notes": ""
        }
    },
]

# ── Domain 4: Alternative Data (5 groups) ────────────────────────────────────

DOMAIN_4 = [
    {
        "group_id": 1,
        "domain": "alternative_data",
        "L3": {
            "title": "Satellite Parking Lot Analytics",
            "text": "Satellite retail signal: ingest weekly parking lot imagery for 4,200 US retail locations from Orbital Insight feed; compute occupancy delta vs trailing 8-week average; go long retailers where aggregate occupancy z-score > 1.6 AND credit card transaction growth (Mastercard SpendPulse) confirms > +5% YoY in same geography; position 0.9% NAV; entry 15 days before quarterly earnings; exit at earnings +2 days; alpha decay estimate: signal loses 60% predictive power after 20 days post-observation; Universe: 35 US brick-and-mortar retailers in Consumer Discretionary, min $5B mktcap. Weight: 60% satellite, 40% credit card.",
            "notes": "Multi-source alt data: satellite + credit card, with alpha decay model and signal weighting"
        },
        "L2": {
            "title": "Satellite + Transaction Data Signals",
            "text": "We combine satellite-derived retail foot traffic data with credit card transaction signals to anticipate quarterly results for brick-and-mortar retailers. Multi-source confirmation improves signal reliability, and we model alpha decay to optimize entry timing.",
            "notes": ""
        },
        "L1": {
            "title": "Satellite Data in Investing",
            "text": "Satellite imagery analysis, such as counting cars in retail parking lots, provides alternative measures of business activity. This data can offer early signals about company performance before official reports.",
            "notes": ""
        }
    },
    {
        "group_id": 2,
        "domain": "alternative_data",
        "L3": {
            "title": "NLP Earnings Call Sentiment",
            "text": "Earnings call NLP: process transcripts within 30 minutes of filing using fine-tuned FinBERT model (internal, trained on 12K annotated transcripts); extract management sentiment score [-1, +1], uncertainty word frequency, and forward-looking statement ratio; trade signal: go long if composite NLP score > +0.35 AND prior quarter score was < +0.15 (sentiment improvement); position 0.7% NAV; hold 8 trading days; stop at -2.5%; add hedonic regression residual (sentiment vs market reaction) to filter false positives; Universe: Russell 1000, English transcripts only; model retrained quarterly with last 3 years data.",
            "notes": "Proprietary NLP model with specific architecture, training set, composite scoring thresholds"
        },
        "L2": {
            "title": "NLP Earnings Transcript Analysis",
            "text": "We apply natural language processing to earnings call transcripts, extracting sentiment and linguistic features using a custom-trained model. Trading signals combine absolute sentiment levels with quarter-over-quarter changes, filtered by market reaction residuals.",
            "notes": ""
        },
        "L1": {
            "title": "NLP in Financial Analysis",
            "text": "Natural language processing can analyze earnings call transcripts to detect management tone and sentiment changes. Research shows linguistic features correlate with future stock performance beyond quantitative metrics alone.",
            "notes": ""
        }
    },
    {
        "group_id": 3,
        "domain": "alternative_data",
        "L3": {
            "title": "Web Traffic + App Download Signals",
            "text": "Digital engagement signal: ingest weekly SimilarWeb traffic estimates AND Sensor Tower app download data for 120 US tech/e-commerce companies; construct composite digital engagement z-score = 0.5 * web_traffic_delta + 0.3 * app_download_delta + 0.2 * app_rating_change; go long if z-score > 1.4 AND trailing 3M revenue estimate revision is non-negative; position 0.8% NAV; entry at signal date, exit after 15 trading days or at next earnings (whichever first); stop at -4%; alpha decay: 45% power loss after 10 days; Universe: US-listed tech with > 50% digital revenue, min $3B mktcap.",
            "notes": "Multi-source digital engagement composite with specific weights, decay model, revenue revision filter"
        },
        "L2": {
            "title": "Digital Engagement Alpha",
            "text": "Our alternative data strategy combines web traffic and mobile app metrics into a composite digital engagement score for tech and e-commerce companies. Revenue revision filters and alpha decay modeling optimize signal timing and quality.",
            "notes": ""
        },
        "L1": {
            "title": "Web and App Data for Investing",
            "text": "Website traffic and mobile app download trends can provide real-time indicators of company growth. These digital engagement metrics often lead traditional financial reporting by weeks or months.",
            "notes": ""
        }
    },
    {
        "group_id": 4,
        "domain": "alternative_data",
        "L3": {
            "title": "Job Postings as Growth Indicator",
            "text": "Hiring momentum signal: scrape LinkedIn/Indeed daily for 800 US public companies; compute 30D net job posting change normalized by company headcount; go long if hiring z-score > 1.8 AND postings are concentrated in revenue-generating roles (sales, engineering > 60% of new posts) AND company is not in a known restructuring; position 0.6% NAV; hold 25 trading days; stop at -5%; lag adjustment: signal reflects decisions made 2-4 weeks prior, enter 5 days after signal confirmation; Universe: Russell 1000, exclude financial sector; model accuracy: 58% hit rate on 3M forward returns, IR 0.7.",
            "notes": "Job posting signal with role-type filter, headcount normalization, lag adjustment, historical IR"
        },
        "L2": {
            "title": "Hiring Momentum Strategy",
            "text": "We analyze corporate job posting patterns as leading indicators of business confidence and growth. Role-type classification distinguishes growth hiring from backfill, and headcount normalization enables cross-company comparison.",
            "notes": ""
        },
        "L1": {
            "title": "Job Market Data in Investing",
            "text": "Corporate hiring activity, tracked through job posting data, can serve as a leading indicator of business expansion plans. Rapid increases in technical or sales hiring often precede revenue growth.",
            "notes": ""
        }
    },
    {
        "group_id": 5,
        "domain": "alternative_data",
        "L3": {
            "title": "Supply Chain Shipping + IoT Data",
            "text": "Supply chain signal: ingest AIS vessel tracking data (MarineTraffic API) for 850 container/bulk cargo routes AND IoT sensor data from partner logistics providers covering 12,000 US warehouse locations; compute supply chain velocity index = (port_throughput_delta * 0.4 + warehouse_utilization_delta * 0.35 + trucking_rate_change * 0.25); go long industrials/materials when velocity z-score > 1.5, short when < -1.5; position 1.0% NAV per leg; hold 20 trading days; rebalance monthly; alpha lead time: 3-6 weeks ahead of PMI; Universe: 40 US industrials/materials, min $5B mktcap.",
            "notes": "Multi-source supply chain composite: shipping, warehouse IoT, trucking rates with specific weights"
        },
        "L2": {
            "title": "Supply Chain Intelligence",
            "text": "We aggregate shipping vessel data, warehouse utilization metrics, and freight rates into a composite supply chain velocity index. This leading indicator anticipates industrial sector performance ahead of traditional economic surveys.",
            "notes": ""
        },
        "L1": {
            "title": "Supply Chain Data in Investing",
            "text": "Supply chain data such as shipping volumes and freight rates can serve as leading economic indicators. Tracking goods movement provides early signals about industrial production and trade activity.",
            "notes": ""
        }
    },
]

# ── Domain 5: Factor Neutral (5 groups) ──────────────────────────────────────

DOMAIN_5 = [
    {
        "group_id": 1,
        "domain": "factor_neutral",
        "L3": {
            "title": "Market Neutral: Factor Exposure Limits",
            "text": "Market neutral constraints: portfolio beta to SPX < |0.05|, beta to Russell 2000 < |0.08|; sector deviation from benchmark < 2% AUM per GICS sector; style factor exposures (Barra USE4): |Size| < 0.15 std, |Value| < 0.20 std, |Momentum| < 0.25 std, |Volatility| < 0.20 std; rebalance trigger: any factor exceeds 80% of limit; hedge instruments: ES futures (beta), sector ETFs (industry); rebalance cost budget 3 bps per event; max rebalances 3 per week; gross exposure 190% NAV, net < |3%|. Compliance check at 16:15 ET daily.",
            "notes": "Complete factor neutralization spec: Barra factors, specific exposure limits, rebalance triggers"
        },
        "L2": {
            "title": "Multi-Factor Neutralization Framework",
            "text": "Our market-neutral portfolio maintains strict limits on beta, sector, and style factor exposures using a commercial risk model. Automated rebalancing triggers when any exposure approaches its limit, using futures and ETF overlays as hedge instruments.",
            "notes": ""
        },
        "L1": {
            "title": "Factor Neutralization Basics",
            "text": "Factor-neutral portfolios aim to eliminate systematic risk exposures (market, size, value, momentum) to isolate idiosyncratic stock-picking alpha. Risk models quantify factor exposures for monitoring.",
            "notes": ""
        }
    },
    {
        "group_id": 2,
        "domain": "factor_neutral",
        "L3": {
            "title": "Dollar Neutral L/S with Risk Parity",
            "text": "Dollar-neutral long/short: 120 longs, 80 shorts; long leg weighted by inverse volatility (60D realized vol), short leg equal-weighted; gross exposure 160% NAV; dollar-neutral tolerance ±$500K; daily P&L attribution required across 6 factors (Market, Size, Value, Momentum, Quality, Low Vol); if unexplained residual P&L > 40% for 3 consecutive days, flag for PM review; borrowing cost cap: 200 bps annualized for shorts, replace names exceeding cap; portfolio turnover target 25% monthly; Universe: Russell 1000, min $2B mktcap.",
            "notes": "Risk-parity weighting, P&L attribution thresholds, borrow cost management rules"
        },
        "L2": {
            "title": "Dollar-Neutral Risk Parity",
            "text": "Our long-short portfolio uses inverse-volatility weighting on the long side with dollar-neutral construction. Daily P&L factor attribution monitors unexplained alpha, and automatic flags trigger review when residual attribution exceeds threshold.",
            "notes": ""
        },
        "L1": {
            "title": "Dollar-Neutral Portfolios",
            "text": "Dollar-neutral strategies maintain equal dollar amounts on long and short sides, eliminating market directional exposure. This construction isolates the manager's stock selection skill from market timing.",
            "notes": ""
        }
    },
    {
        "group_id": 3,
        "domain": "factor_neutral",
        "L3": {
            "title": "Dynamic Hedging: Tail Risk Overlay",
            "text": "Tail risk overlay: maintain 2% NAV in SPX put spreads (3M expiry, 5% OTM / 15% OTM); roll at 30 DTE; if VIX crosses above 25, increase allocation to 3.5% NAV and shift strikes to 3% OTM / 10% OTM; if VIX crosses above 35, add 1% NAV in VIX call spreads (30/50 strike); total hedging budget cap: 55 bps annual drag; hedge effectiveness target: cover ≥ 30% of portfolio drawdown in SPX drops > 10%; quarterly backtest vs realized drawdowns; adjust strikes if skew z-score (25D put vs ATM) exceeds 1.5.",
            "notes": "Dynamic tail hedge with VIX regime escalation, skew adjustment, effectiveness targets"
        },
        "L2": {
            "title": "Dynamic Tail Risk Hedging",
            "text": "Our tail risk overlay uses put spreads with dynamic strike adjustment based on VIX regimes and skew levels. Hedging allocation scales up during stress periods, with strict budget constraints and quarterly effectiveness monitoring against realized drawdowns.",
            "notes": ""
        },
        "L1": {
            "title": "Portfolio Tail Risk Hedging",
            "text": "Tail risk hedging uses options strategies to protect against extreme market declines. Put spreads and VIX derivatives are common tools that provide asymmetric payoffs during market stress events.",
            "notes": ""
        }
    },
    {
        "group_id": 4,
        "domain": "factor_neutral",
        "L3": {
            "title": "Cross-Asset Correlation Regime",
            "text": "Correlation regime management: monitor rolling 60D correlation between portfolio and 8 macro factors (US 10Y yield, DXY, WTI crude, gold, HY spread, VIX, EM equity, copper); if average absolute correlation rises above 0.25 (from normal 0.12), activate de-risking protocol: reduce gross exposure from 190% to 140% NAV over 3 days, tighten single-name stops from -5% to -3%, increase cash buffer from 5% to 12%; re-engage when avg correlation falls below 0.18 for 5 consecutive days; log all regime transitions in internal REGIME_LOG with timestamp and trigger values.",
            "notes": "Cross-asset correlation regime detection with specific macro factors, de-risking protocol thresholds"
        },
        "L2": {
            "title": "Correlation Regime Risk Management",
            "text": "We monitor portfolio correlation with macro factors to detect regime shifts. When correlations spike above normal levels, an automated de-risking protocol reduces exposure and tightens stops. Re-engagement follows sustained correlation normalization.",
            "notes": ""
        },
        "L1": {
            "title": "Correlation and Regime Risk",
            "text": "During market stress, correlations between asset classes tend to increase, reducing diversification benefits. Monitoring correlation regimes helps portfolio managers adjust risk exposures proactively.",
            "notes": ""
        }
    },
    {
        "group_id": 5,
        "domain": "factor_neutral",
        "L3": {
            "title": "Industry Neutral Alpha Capture",
            "text": "Industry-neutral alpha: within each of 24 GICS industry groups, rank stocks by composite alpha score (40% earnings revision breadth + 30% short interest decrease + 30% insider buying ratio); go long top quintile, short bottom quintile within each industry; equal-weight within quintiles; resulting portfolio: zero industry exposure by construction; target 80-100 names per leg; rebalance bi-weekly; expected gross alpha 6-8% annualized, IR target 1.2; max single-name 1.0% NAV; screen: min $1B mktcap, min $5M ADTV; recalibrate alpha weights quarterly using trailing 2Y IC.",
            "notes": "Industry-neutral construction with composite alpha weights, IC-based recalibration"
        },
        "L2": {
            "title": "Industry-Neutral Alpha Portfolio",
            "text": "Our industry-neutral strategy ranks stocks within each GICS industry group using a multi-factor alpha composite, ensuring zero industry exposure by construction. Alpha factor weights are recalibrated quarterly based on information coefficient analysis.",
            "notes": ""
        },
        "L1": {
            "title": "Industry-Neutral Investing",
            "text": "Industry-neutral portfolios select stocks within each industry rather than across industries, eliminating sector allocation as a return driver. This isolates stock-picking skill from sector rotation effects.",
            "notes": ""
        }
    },
]

# ── Domain 6: ML Signals (5 groups) ─────────────────────────────────────────

DOMAIN_6 = [
    {
        "group_id": 1,
        "domain": "ml_signals",
        "L3": {
            "title": "Gradient Boosted Stock Selection",
            "text": "ML stock selection (GBM): LightGBM model with 47 features spanning price/volume (12), fundamental (15), analyst (8), and alternative data (12); target: 5D forward return quintile classification; training: rolling 3Y window, retrain monthly, 5-fold purged cross-validation with 5-day embargo; feature importance: top-5 are earnings_revision_breadth, 60d_abnormal_volume, short_interest_change, insider_buy_ratio, credit_spread_sector; signal threshold: go long predicted top decile (score > 0.72), short bottom decile (score < 0.28); position 0.5% NAV per name; degradation rule: if rolling 60D IC drops below 0.02, switch to rules-based fallback (simple momentum + quality); Universe: Russell 1000, 800+ names.",
            "notes": "Complete ML pipeline: model type, feature count, training protocol, degradation fallback"
        },
        "L2": {
            "title": "ML-Driven Stock Selection",
            "text": "Our quantitative team uses a gradient boosted model trained on price, fundamental, analyst, and alternative data features to predict short-term stock returns. Purged cross-validation prevents lookahead bias, and automated model degradation detection triggers fallback to rules-based signals.",
            "notes": ""
        },
        "L1": {
            "title": "Machine Learning in Stock Selection",
            "text": "Gradient boosted trees are popular in quantitative finance for combining diverse features into stock return predictions. Careful cross-validation with temporal awareness prevents overfitting to historical data.",
            "notes": ""
        }
    },
    {
        "group_id": 2,
        "domain": "ml_signals",
        "L3": {
            "title": "LSTM Regime Detection",
            "text": "Regime detection (LSTM): 2-layer LSTM (128 hidden units each) trained on 15 daily market features (VIX, term structure slope, credit spreads, put-call ratio, breadth, sector dispersion, etc.); output: 4-regime classification (risk-on trending, risk-on mean-reverting, risk-off trending, risk-off mean-reverting); confidence threshold: act on regime signal only if softmax probability > 0.65; training: 10Y daily data, walk-forward with 6M test windows; regime dictates strategy allocation: risk-on trending → 70% momentum + 30% breakout; risk-off → 80% mean-reversion + 20% defensive; transition buffer: require 3 consecutive same-regime signals before switching; update model quarterly.",
            "notes": "LSTM architecture, regime taxonomy, strategy allocation mapping, transition rules"
        },
        "L2": {
            "title": "Neural Network Regime Detection",
            "text": "We employ a recurrent neural network to classify market regimes using a broad set of market indicators. Each regime maps to a different strategy allocation mix, with transition buffers preventing whipsaw from noisy regime changes.",
            "notes": ""
        },
        "L1": {
            "title": "Regime Detection in Finance",
            "text": "Financial markets exhibit different behavioral regimes (trending vs mean-reverting, high vs low volatility). Machine learning models can identify these regimes to adapt trading strategy selection dynamically.",
            "notes": ""
        }
    },
    {
        "group_id": 3,
        "domain": "ml_signals",
        "L3": {
            "title": "Transformer Earnings Prediction",
            "text": "Earnings prediction (Transformer): custom 6-layer transformer with attention over trailing 8 quarters of financial data + 90 days of price/volume features + recent analyst estimate revisions; output: probability of earnings beat/miss (binary) + predicted surprise magnitude; training set: 45K quarterly observations (2010-2024), walk-forward validation; act on P(beat) > 0.68 AND predicted surprise > +4%; position 1.0% NAV pre-earnings, entry at Day-3; exit at Day+2 post-earnings; stop: exit if stock drops > 2% pre-earnings; max 10 concurrent pre-earnings positions; model AUC: 0.71 on out-of-sample; retrain quarterly with new earnings data.",
            "notes": "Transformer architecture for earnings prediction with specific layers, data windows, AUC metrics"
        },
        "L2": {
            "title": "Deep Learning Earnings Prediction",
            "text": "Our earnings prediction model uses a transformer architecture that processes multi-quarter financial sequences alongside market data and analyst revisions. The model outputs both beat/miss probability and surprise magnitude, enabling pre-earnings positioning with quantified confidence.",
            "notes": ""
        },
        "L1": {
            "title": "ML for Earnings Forecasting",
            "text": "Machine learning models can combine fundamental data, analyst estimates, and market signals to predict earnings surprises. Deep learning architectures capture complex nonlinear patterns across multiple data sources.",
            "notes": ""
        }
    },
    {
        "group_id": 4,
        "domain": "ml_signals",
        "L3": {
            "title": "Reinforcement Learning Execution",
            "text": "RL execution optimizer: PPO agent trained on 18 months of tick data across 500 liquid US stocks; state space: current fill rate, time remaining, spread, queue position, short-term alpha forecast, volatility; action space: limit price offset (0-5 ticks), order size (10-30% of remaining), aggression level (passive/mid/aggressive); reward: implementation shortfall vs arrival price, penalized by market impact; training: 200M simulated episodes with realistic fill models; deployment: handles orders $500K-$10M; expected IS reduction: 1.8 bps vs pure TWAP; fallback: revert to TWAP if RL agent PnL underperforms TWAP by > 3 bps rolling 5D. Model version: EXEC_RL_v3.",
            "notes": "RL execution with PPO, state/action spaces, IS benchmark, performance-based fallback"
        },
        "L2": {
            "title": "RL-Based Trade Execution",
            "text": "Our execution desk uses a reinforcement learning agent to optimize order execution, minimizing implementation shortfall versus arrival price. The agent adapts to real-time market conditions and automatically reverts to benchmark algorithms if performance degrades.",
            "notes": ""
        },
        "L1": {
            "title": "Algorithmic Execution",
            "text": "Algorithmic execution strategies like TWAP and VWAP automate trade execution to minimize market impact. Reinforcement learning represents the frontier of execution optimization, adapting to market microstructure in real time.",
            "notes": ""
        }
    },
    {
        "group_id": 5,
        "domain": "ml_signals",
        "L3": {
            "title": "Ensemble Meta-Learner Portfolio",
            "text": "Meta-learning ensemble: stack 5 base models (LightGBM, XGBoost, Ridge regression, 2-layer MLP, random forest) each generating daily stock scores; meta-learner (logistic regression with L1 regularization, λ=0.01) combines base model outputs with 30D rolling model performance features; final signal: go long if meta-score > 0.62, short if < 0.38; position sizing: Kelly fraction * 0.3 (fractional Kelly) capped at 1.2% NAV; refit meta-learner weekly; base models retrained monthly; if ensemble disagreement (max-min base score) > 0.5, halve position size; Universe: Russell 1000; expected Sharpe: 1.8 gross, 1.3 net; drawdown limit: pause if 30D rolling return < -4%.",
            "notes": "Full ensemble stack: 5 base models, meta-learner spec, Kelly sizing, disagreement rule"
        },
        "L2": {
            "title": "Ensemble Model Portfolio Construction",
            "text": "We use a stacked ensemble of diverse machine learning models combined by a meta-learner that adapts weights based on recent model performance. Position sizing follows fractional Kelly criterion, and ensemble disagreement triggers automatic risk reduction.",
            "notes": ""
        },
        "L1": {
            "title": "Ensemble Methods in Finance",
            "text": "Ensemble methods combine predictions from multiple models to improve accuracy and robustness. In quantitative finance, stacking diverse model types (tree-based, linear, neural) reduces model-specific risk.",
            "notes": ""
        }
    },
]

# ── Assembly ─────────────────────────────────────────────────────────────────

ALL_DOMAINS = [DOMAIN_1, DOMAIN_2, DOMAIN_3, DOMAIN_4, DOMAIN_5, DOMAIN_6]

DOMAIN_META = {
    "price_volume_momentum": {"category": "strategy_logic", "tags_base": ["momentum", "technical", "volume"]},
    "event_driven": {"category": "strategy_logic", "tags_base": ["event", "earnings", "catalyst"]},
    "statistical_arbitrage": {"category": "strategy_logic", "tags_base": ["stat_arb", "pairs", "mean_reversion"]},
    "alternative_data": {"category": "strategy_logic", "tags_base": ["alt_data", "satellite", "nlp"]},
    "factor_neutral": {"category": "risk_model", "tags_base": ["factor", "neutralization", "market_neutral"]},
    "ml_signals": {"category": "strategy_logic", "tags_base": ["ml", "feature_engineering", "model"]},
}

LEVEL_META = {
    "L3": {"sensitivity_level": 3, "trust_score": 1.0, "source_type": "internal", "style": "parametric", "sensitivity": "top_secret"},
    "L2": {"sensitivity_level": 2, "trust_score": 0.8, "source_type": "internal", "style": "descriptive", "sensitivity": "confidential"},
    "L1": {"sensitivity_level": 1, "trust_score": 0.5, "source_type": "public", "style": "educational", "sensitivity": "practitioner"},
}


def main():
    all_secrets = []

    for domain_groups in ALL_DOMAINS:
        domain_name = domain_groups[0]["domain"]
        meta = DOMAIN_META[domain_name]

        for group in domain_groups:
            for level in ["L3", "L2", "L1"]:
                entry = group[level].copy()
                lmeta = LEVEL_META[level]

                # Build v1-compatible record
                record = {
                    "_id": entry.get("id", f"v2_{level}_{domain_name}_{group['group_id']:03d}"),
                    "title": entry["title"],
                    "text": entry["text"],
                    "source_type": lmeta["source_type"],
                    "trust_score": lmeta["trust_score"],
                    "sensitivity_level": lmeta["sensitivity_level"],
                    "category": meta["category"],
                    "tags": meta["tags_base"].copy(),
                    "style": lmeta["style"],
                    "level": level,
                    "domain": domain_name,
                    "group_id": group["group_id"],
                    "sensitivity": lmeta["sensitivity"],
                    "notes": entry.get("notes", ""),
                }
                all_secrets.append(record)

    # Save
    output_path = "data/secrets/secrets_v2.jsonl"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, 'w') as f:
        for secret in all_secrets:
            f.write(json.dumps(secret, ensure_ascii=False) + '\n')

    print(f"Saved {len(all_secrets)} secrets to {output_path}")

    # Stats
    by_level = {}
    by_domain = {}
    for s in all_secrets:
        level = s['level']
        domain = s['domain']
        by_level[level] = by_level.get(level, 0) + 1
        by_domain[domain] = by_domain.get(domain, 0) + 1

    print(f"By level: {by_level}")
    print(f"By domain: {by_domain}")


if __name__ == '__main__':
    main()
