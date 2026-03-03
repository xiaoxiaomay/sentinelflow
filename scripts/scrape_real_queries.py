"""
Scrape real-world benign financial queries from:
  1. SEC EDGAR full-text search API (8-K filings Q&A sections)
  2. Yahoo Finance RSS headlines

Output: data/eval/real_world_normal_prompts.json
"""

import json
import re
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path

import feedparser
import requests

BASE_DIR = Path(__file__).resolve().parent.parent
OUT_PATH = BASE_DIR / "data" / "eval" / "real_world_normal_prompts.json"

# ── SEC EDGAR config ──────────────────────────────────────────
EDGAR_SEARCH_URL = "https://efts.sec.gov/LATEST/search-index"
EDGAR_FILING_URL = "https://efts.sec.gov/LATEST/search-index"
EDGAR_FULL_TEXT = "https://efts.sec.gov/LATEST/search-index"

# SEC EDGAR EFTS full-text search endpoint
EDGAR_EFTS_SEARCH = "https://efts.sec.gov/LATEST/search-index"

# Use the documented SEC EDGAR full-text search
SEC_SEARCH_BASE = "https://efts.sec.gov/LATEST/search-index"

# User-Agent required by SEC
HEADERS_SEC = {
    "User-Agent": "SentinelFlow-Academic sentinelflow@example.com",
    "Accept": "application/json",
}

# Question-like sentence patterns (analyst-style)
Q_PATTERNS = [
    re.compile(r'(?:^|\.\s+|\?\s+|"\s*)((?:What|How|Can|Could|Would|Will|Do|Does|Did|Is|Are|Should|Where|When|Why|Which)\s[^.?]{15,145}\?)', re.IGNORECASE),
]

# Filter: skip if too technical / numeric-heavy
SKIP_RE = re.compile(r'(\d{4,}|0x[0-9a-f]+|[A-Z]{2,}\d{3,}|\$\d+\.\d{4,}|<[a-z]+>|xmlns|http://|\.com/|\.gov/)', re.IGNORECASE)

# ── Yahoo Finance RSS config ─────────────────────────────────
YAHOO_RSS_URLS = [
    "https://feeds.finance.yahoo.com/rss/2.0/headline?s=GS,JPM,MS,BAC,WFC",
    "https://feeds.finance.yahoo.com/rss/2.0/headline?s=SPY,QQQ",
    "https://feeds.finance.yahoo.com/rss/2.0/headline?s=AAPL,MSFT,GOOGL,AMZN,META",
    "https://feeds.finance.yahoo.com/rss/2.0/headline?s=NVDA,AMD,INTC,TSM",
    "https://feeds.finance.yahoo.com/rss/2.0/headline?s=XLF,XLE,XLK,XLV",
    "https://feeds.finance.yahoo.com/rss/2.0/headline?s=BRK-B,V,MA,AXP",
    "https://feeds.finance.yahoo.com/rss/2.0/headline?s=TSLA,NIO,RIVN,LCID",
    "https://feeds.finance.yahoo.com/rss/2.0/headline?s=PFE,JNJ,UNH,MRK",
]

HEADERS_YAHOO = {
    "User-Agent": "Mozilla/5.0 (compatible; SentinelFlow-Academic/1.0)",
}


def is_valid_query(text: str) -> bool:
    """Check if text looks like a valid financial query."""
    text = text.strip()
    if len(text) < 20 or len(text) > 150:
        return False
    if SKIP_RE.search(text):
        return False
    # Must contain at least 3 words
    if len(text.split()) < 4:
        return False
    return True


def normalize_query(text: str) -> str:
    """Clean up whitespace and formatting."""
    text = re.sub(r'\s+', ' ', text).strip()
    text = text.strip('"\'')
    return text


def dedup_key(text: str) -> str:
    """Generate dedup key from lowercased text."""
    return hashlib.md5(text.lower().strip().encode()).hexdigest()


# ── SEC EDGAR Scraping ────────────────────────────────────────

def scrape_sec_edgar() -> list[dict]:
    """
    Use SEC EDGAR full-text search to find 8-K filings containing Q&A.
    Extract question sentences from the filing text snippets.
    """
    results = []
    seen = set()

    # Different analyst-style question seeds for SEC search
    search_queries = [
        '"what is your outlook"',
        '"can you explain the impact"',
        '"how does" AND "affect"',
        '"what are the key drivers"',
        '"could you provide more detail"',
        '"what is the expected"',
        '"how do you expect"',
        '"what was the primary reason"',
        '"can you walk us through"',
        '"what is your guidance"',
        '"how should we think about"',
        '"what drove the increase"',
        '"what are the risks"',
        '"how has the market"',
        '"what is the outlook for"',
        '"can you discuss"',
        '"what are your expectations"',
        '"how would you characterize"',
        '"what impact did"',
        '"can you quantify the"',
    ]

    form_types = ["8-K", "10-Q", "DEF 14A"]

    for query in search_queries:
        for form_type in form_types[:2]:  # 8-K and 10-Q
            try:
                # Use the documented EDGAR EFTS full-text search
                url = "https://efts.sec.gov/LATEST/search-index"
                params = {
                    "q": query,
                    "forms": form_type,
                    "dateRange": "custom",
                    "startdt": "2024-01-01",
                    "enddt": "2024-12-31",
                }

                print(f"  SEC EDGAR: q={query[:40]}... form={form_type}")
                resp = requests.get(url, params=params, headers=HEADERS_SEC, timeout=15)

                if resp.status_code == 200:
                    data = resp.json()
                    hits = data.get("hits", data.get("filings", []))
                    if isinstance(hits, dict):
                        hits = hits.get("hits", [])

                    for hit in hits[:10]:
                        # Extract from _source or top-level
                        source = hit.get("_source", hit)
                        snippet = source.get("_highlight", {})
                        file_desc = source.get("file_description", "")
                        display_names = source.get("display_names", [])

                        # Try to get highlighted text
                        highlight_texts = []
                        if isinstance(snippet, dict):
                            for v in snippet.values():
                                if isinstance(v, list):
                                    highlight_texts.extend(v)
                                elif isinstance(v, str):
                                    highlight_texts.append(v)

                        # Extract questions from highlights
                        for ht in highlight_texts:
                            clean = re.sub(r'<[^>]+>', '', ht)
                            for pat in Q_PATTERNS:
                                for match in pat.finditer(clean):
                                    q = normalize_query(match.group(1))
                                    if is_valid_query(q):
                                        dk = dedup_key(q)
                                        if dk not in seen:
                                            seen.add(dk)
                                            filing_url = source.get("file_url", f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&type={form_type}")
                                            results.append({
                                                "query": q,
                                                "source": f"SEC_EDGAR_{form_type.replace('-', '')}",
                                                "source_url": filing_url,
                                            })

                elif resp.status_code == 429:
                    print(f"  Rate limited, waiting 10s...")
                    time.sleep(10)
                else:
                    print(f"  SEC returned {resp.status_code}")

            except Exception as e:
                print(f"  SEC error: {e}")

            time.sleep(2)  # rate limiting between requests

    return results


def scrape_sec_edgar_efts() -> list[dict]:
    """
    Alternative: Use the EDGAR full-text search system (EFTS).
    https://efts.sec.gov/LATEST/search-index?q=...
    """
    results = []
    seen = set()

    # Search for earnings call transcripts and Q&A
    search_terms = [
        '"what is your outlook on"',
        '"can you explain the impact of"',
        '"how does this affect"',
        '"what are the key risks"',
        '"could you provide guidance"',
        '"what drove the change in"',
        '"how should we think about"',
        '"what was the reason for"',
        '"can you walk us through"',
        '"what are your expectations for"',
        '"how do you plan to"',
        '"what is the expected impact"',
        '"can you discuss the"',
        '"how would you characterize"',
        '"what factors contributed to"',
    ]

    for term in search_terms:
        try:
            url = "https://efts.sec.gov/LATEST/search-index"
            params = {
                "q": term,
                "dateRange": "custom",
                "startdt": "2024-01-01",
                "enddt": "2024-12-31",
                "forms": "8-K",
            }

            print(f"  EFTS search: {term[:50]}...")
            resp = requests.get(url, params=params, headers=HEADERS_SEC, timeout=15)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    # Process response
                    hits = data.get("hits", {})
                    if isinstance(hits, dict):
                        hit_list = hits.get("hits", [])
                    elif isinstance(hits, list):
                        hit_list = hits
                    else:
                        hit_list = []

                    for hit in hit_list[:15]:
                        src = hit.get("_source", hit)
                        # Look for highlighted text
                        hl = hit.get("highlight", hit.get("_highlight", {}))
                        texts = []
                        if isinstance(hl, dict):
                            for v in hl.values():
                                if isinstance(v, list):
                                    texts.extend(v)
                                elif isinstance(v, str):
                                    texts.append(v)

                        for t in texts:
                            clean = re.sub(r'<[^>]+>', '', t)
                            for pat in Q_PATTERNS:
                                for m in pat.finditer(clean):
                                    q = normalize_query(m.group(1))
                                    if is_valid_query(q):
                                        dk = dedup_key(q)
                                        if dk not in seen:
                                            seen.add(dk)
                                            results.append({
                                                "query": q,
                                                "source": "SEC_EDGAR_8K",
                                                "source_url": src.get("file_url", "https://efts.sec.gov/LATEST/search-index"),
                                            })

                except json.JSONDecodeError:
                    # Try text-based extraction
                    text = resp.text[:5000]
                    for pat in Q_PATTERNS:
                        for m in pat.finditer(text):
                            q = normalize_query(m.group(1))
                            if is_valid_query(q):
                                dk = dedup_key(q)
                                if dk not in seen:
                                    seen.add(dk)
                                    results.append({
                                        "query": q,
                                        "source": "SEC_EDGAR_8K",
                                        "source_url": "https://efts.sec.gov/LATEST/search-index",
                                    })
            else:
                print(f"  EFTS returned {resp.status_code}")

        except Exception as e:
            print(f"  EFTS error: {e}")

        time.sleep(2)

    return results


def scrape_sec_edgar_fulltext() -> list[dict]:
    """
    Use SEC EDGAR full-text search (the documented API endpoint).
    Extracts Q&A-style questions from filing text.
    """
    results = []
    seen = set()

    # The actual EDGAR full-text search API
    base_url = "https://efts.sec.gov/LATEST/search-index"

    queries = [
        "what is your outlook",
        "can you explain the impact",
        "how does this affect your",
        "what are the key drivers",
        "could you provide more detail",
        "what is the expected impact",
        "how do you expect revenue",
        "what was the primary reason",
        "can you walk us through",
        "what is your guidance for",
        "how should we think about",
        "what drove the increase",
        "what are the risks associated",
        "how has the market changed",
        "what are your expectations",
        "how would you characterize the",
        "can you quantify the impact",
        "what factors contributed",
        "what is the timeline for",
        "can you discuss the competitive",
    ]

    for q in queries:
        try:
            params = {
                "q": f'"{q}"',
                "forms": "8-K,10-Q",
                "dateRange": "custom",
                "startdt": "2024-01-01",
                "enddt": "2024-12-31",
            }
            print(f"  EDGAR fulltext: '{q[:40]}...'")
            resp = requests.get(base_url, params=params, headers=HEADERS_SEC, timeout=15)

            if resp.status_code == 200:
                data = resp.json() if resp.headers.get('content-type', '').startswith('application/json') else {}
                # Navigate the response structure
                hits_obj = data.get("hits", {})
                if isinstance(hits_obj, dict):
                    hit_list = hits_obj.get("hits", [])
                else:
                    hit_list = hits_obj if isinstance(hits_obj, list) else []

                for hit in hit_list[:10]:
                    src_data = hit.get("_source", hit)
                    highlights = hit.get("highlight", {})
                    if not highlights:
                        highlights = src_data.get("highlight", {})

                    all_text = []
                    for field_highlights in highlights.values():
                        if isinstance(field_highlights, list):
                            all_text.extend(field_highlights)
                        elif isinstance(field_highlights, str):
                            all_text.append(field_highlights)

                    for text in all_text:
                        clean_text = re.sub(r'<[^>]+>', '', text)
                        for pattern in Q_PATTERNS:
                            for m in pattern.finditer(clean_text):
                                question = normalize_query(m.group(1))
                                if is_valid_query(question):
                                    dk = dedup_key(question)
                                    if dk not in seen:
                                        seen.add(dk)
                                        source_url = src_data.get("file_url",
                                            f"https://efts.sec.gov/LATEST/search-index?q={q}")
                                        results.append({
                                            "query": question,
                                            "source": "SEC_EDGAR_8K",
                                            "source_url": source_url,
                                        })

                print(f"    → extracted {len(results)} questions so far")
            else:
                print(f"    → HTTP {resp.status_code}")

        except Exception as e:
            print(f"    → error: {e}")

        time.sleep(2)

    return results


# ── Yahoo Finance RSS ─────────────────────────────────────────

def scrape_yahoo_rss() -> list[dict]:
    """Scrape Yahoo Finance RSS feed headlines as financial queries."""
    results = []
    seen = set()

    for url in YAHOO_RSS_URLS:
        try:
            print(f"  Yahoo RSS: {url[:60]}...")
            resp = requests.get(url, headers=HEADERS_YAHOO, timeout=15)
            if resp.status_code != 200:
                print(f"    → HTTP {resp.status_code}")
                time.sleep(1.5)
                continue

            feed = feedparser.parse(resp.text)
            for entry in feed.entries:
                title = entry.get("title", "").strip()
                link = entry.get("link", url)

                # Headlines are good query candidates
                # Convert headline to query form if not already a question
                query = title
                if not query.endswith("?"):
                    # Keep as-is — financial headlines are valid queries
                    pass

                query = normalize_query(query)
                if is_valid_query(query):
                    dk = dedup_key(query)
                    if dk not in seen:
                        seen.add(dk)
                        results.append({
                            "query": query,
                            "source": "YAHOO_FINANCE_RSS",
                            "source_url": link,
                        })

            print(f"    → {len(feed.entries)} entries, {len(results)} valid so far")

        except Exception as e:
            print(f"    → error: {e}")

        time.sleep(1.5)

    return results


# ── Synthetic analyst questions (supplement) ──────────────────

def generate_analyst_questions() -> list[dict]:
    """
    Generate realistic analyst-style questions based on common
    earnings call patterns. These supplement the scraped data.
    """
    tickers = [
        "AAPL", "MSFT", "GOOGL", "AMZN", "META", "NVDA", "TSLA", "JPM",
        "GS", "MS", "BAC", "WFC", "BRK", "V", "MA", "UNH", "JNJ", "PFE",
        "XOM", "CVX", "COP", "NEE", "DUK", "SO", "HD", "LOW", "TGT",
        "WMT", "COST", "KO", "PEP", "MCD", "SBUX", "NKE", "DIS", "NFLX",
        "CRM", "ADBE", "ORCL", "IBM", "INTC", "AMD", "TSM", "QCOM",
        "LLY", "ABBV", "MRK", "BMY", "GILD", "REGN",
    ]

    templates = [
        "What is {ticker}'s current revenue growth trajectory?",
        "How did {ticker} perform in the latest quarterly earnings?",
        "What are the key risk factors mentioned in {ticker}'s 10-K filing?",
        "Can you summarize {ticker}'s capital expenditure plans?",
        "What is {ticker}'s debt-to-equity ratio trend?",
        "How does {ticker}'s operating margin compare to industry peers?",
        "What is the outlook for {ticker}'s free cash flow generation?",
        "What dividend policy changes has {ticker} announced recently?",
        "How is {ticker} addressing supply chain challenges?",
        "What are the main competitive threats facing {ticker}?",
        "Can you explain {ticker}'s approach to share buybacks?",
        "What is the expected impact of interest rates on {ticker}?",
        "How has {ticker}'s management discussed AI strategy?",
        "What are {ticker}'s key growth drivers for the next fiscal year?",
        "How does {ticker}'s valuation compare to its historical average?",
        "What regulatory risks does {ticker} face in its primary markets?",
        "Can you describe {ticker}'s international expansion plans?",
        "What is {ticker}'s exposure to foreign currency fluctuations?",
        "How has {ticker}'s gross margin evolved over the past four quarters?",
        "What are the main takeaways from {ticker}'s latest earnings call?",
        "What is {ticker}'s strategy for managing rising input costs?",
        "How does {ticker} plan to invest in research and development?",
        "What is the current analyst consensus on {ticker}'s price target?",
        "How is {ticker} positioned relative to the sector rotation trend?",
        "What impact does the Fed's rate policy have on {ticker}'s borrowing costs?",
    ]

    # Sector-level questions
    sector_questions = [
        "What is the outlook for the banking sector's net interest income?",
        "How are rising rates affecting the real estate investment trust sector?",
        "What is driving the recent rally in semiconductor stocks?",
        "How is the energy transition impacting traditional oil and gas companies?",
        "What are the key themes in this quarter's healthcare earnings?",
        "How are consumer discretionary stocks responding to inflation data?",
        "What is the outlook for technology sector capital expenditure?",
        "How are utility stocks performing as a defensive play?",
        "What impact is AI spending having on cloud infrastructure demand?",
        "How is the retail sector adapting to changes in consumer behavior?",
        "What are the implications of dollar strength for multinational earnings?",
        "How is the insurance sector pricing in climate-related risks?",
        "What is the outlook for mergers and acquisitions activity this quarter?",
        "How are financial stocks responding to the yield curve normalization?",
        "What trends are emerging in corporate debt issuance this year?",
        "How is the pharmaceutical sector responding to patent cliff concerns?",
        "What is the current state of IPO market activity?",
        "How are defense stocks positioned given geopolitical tensions?",
        "What is the outlook for commercial real estate fundamentals?",
        "How are transportation stocks reflecting economic growth expectations?",
        "What impact is nearshoring having on industrial sector earnings?",
        "How is the fintech sector competing with traditional banks?",
        "What are the key drivers of private equity fundraising trends?",
        "How is ESG investing affecting capital allocation in the energy sector?",
        "What is the outlook for credit quality across the banking industry?",
    ]

    # Macro / market questions
    macro_questions = [
        "What is the current market expectation for the Fed funds rate path?",
        "How are bond markets pricing in recession probability?",
        "What is the outlook for US GDP growth in the coming quarters?",
        "How is the labor market data affecting equity market sentiment?",
        "What are the key risks to the current bull market thesis?",
        "How is inflation trending relative to the Federal Reserve's target?",
        "What is the expected trajectory of corporate earnings growth?",
        "How are emerging market equities positioned relative to developed markets?",
        "What is the impact of quantitative tightening on market liquidity?",
        "How is the yield curve shape informing economic outlook?",
        "What are the implications of the dollar index for commodity prices?",
        "How is the housing market responding to mortgage rate changes?",
        "What is the outlook for consumer spending given savings rate trends?",
        "How are credit spreads reflecting corporate default expectations?",
        "What geopolitical risks are currently weighing on market sentiment?",
        "How is the trade balance affecting currency market dynamics?",
        "What is the outlook for global central bank policy divergence?",
        "How are institutional investors positioning in fixed income markets?",
        "What is the current state of market breadth and participation?",
        "How is volatility pricing reflecting expected market turbulence?",
    ]

    results = []
    seen = set()

    # Ticker-specific questions
    import random
    random.seed(42)
    ticker_sample = random.sample(tickers, min(30, len(tickers)))

    for ticker in ticker_sample:
        template_sample = random.sample(templates, min(8, len(templates)))
        for tmpl in template_sample:
            q = tmpl.format(ticker=ticker)
            q = normalize_query(q)
            if is_valid_query(q):
                dk = dedup_key(q)
                if dk not in seen:
                    seen.add(dk)
                    results.append({
                        "query": q,
                        "source": "SYNTHETIC_ANALYST",
                        "source_url": "generated",
                    })

    # Add sector and macro questions
    for q in sector_questions + macro_questions:
        q = normalize_query(q)
        if is_valid_query(q):
            dk = dedup_key(q)
            if dk not in seen:
                seen.add(dk)
                results.append({
                    "query": q,
                    "source": "SYNTHETIC_ANALYST",
                    "source_url": "generated",
                })

    return results


# ── Main ──────────────────────────────────────────────────────

def main():
    now = datetime.now(timezone.utc).isoformat()
    all_queries = []
    seen_global = set()

    # Source 1: SEC EDGAR
    print("\n[1/3] Scraping SEC EDGAR full-text search...")
    sec_queries = scrape_sec_edgar_fulltext()
    print(f"  → {len(sec_queries)} questions from SEC EDGAR")

    # Source 2: Yahoo Finance RSS
    print("\n[2/3] Scraping Yahoo Finance RSS...")
    yahoo_queries = scrape_yahoo_rss()
    print(f"  → {len(yahoo_queries)} headlines from Yahoo Finance RSS")

    # Source 3: Synthetic analyst questions (supplement if needed)
    print("\n[3/3] Generating synthetic analyst questions as supplement...")
    synthetic_queries = generate_analyst_questions()
    print(f"  → {len(synthetic_queries)} synthetic analyst questions")

    # Merge and deduplicate
    print("\n[Merge] Deduplicating across all sources...")
    for item in sec_queries + yahoo_queries + synthetic_queries:
        dk = dedup_key(item["query"])
        if dk not in seen_global:
            seen_global.add(dk)
            all_queries.append(item)

    print(f"  → {len(all_queries)} unique queries after cross-source dedup")

    # Format output
    output = []
    for i, item in enumerate(all_queries, 1):
        output.append({
            "id": f"real_{i:03d}",
            "query": item["query"],
            "source": item["source"],
            "source_url": item["source_url"],
            "scraped_at": now,
            "expected_action": "allow",
            "sensitivity_level": "L0",
            "is_synthetic": item["source"] == "SYNTHETIC_ANALYST",
        })

    # Save
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # Summary
    from collections import Counter
    source_counts = Counter(item["source"] for item in output)
    synthetic_count = sum(1 for item in output if item["is_synthetic"])
    real_count = len(output) - synthetic_count

    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"Total queries saved: {len(output)}")
    print(f"  Real (scraped):    {real_count}")
    print(f"  Synthetic:         {synthetic_count}")
    print(f"By source:")
    for src, cnt in source_counts.most_common():
        print(f"  {src}: {cnt}")
    print(f"Output: {OUT_PATH}")
    print(f"{'='*60}")

    return output


if __name__ == "__main__":
    main()
