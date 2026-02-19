import os
import yaml
import asyncio
import httpx
import feedparser
import trafilatura
import psycopg2
import re
import random
import uuid
from datetime import datetime
from pgvector.psycopg2 import register_vector
from sentence_transformers import SentenceTransformer

# agent pool
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
]

# --- 1. Load Configuration ---
def load_config():
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    current_dir = os.path.dirname(current_script_dir)
    config_path = os.path.join(current_dir, "..", "config.yaml")
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found at {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


cfg = load_config()
db_cfg = cfg.get("db", {})
model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')


# --- 2. Helper: Ticker & Metadata Extraction ---
def extract_ticker(text):
    match = re.search(r'\$([A-Z]{1,5})', text)
    if not match:
        match = re.search(r'\(([A-Z]{1,5})\)', text)
    return match.group(1) if match else "GENERIC"


# --- 3. Enhanced Main Scraper Task ---
async def process_source(source, db_conn):
    source_id, site_name, rss_url = source
    print(f"[*] Starting task for: {site_name}")
    ingested_count = 0

    # 使用更真实的浏览器 Headers
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://finance.yahoo.com/",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True, headers=headers) as client:
        try:
            resp = await client.get(rss_url)
            feed = feedparser.parse(resp.text)
            cur = db_conn.cursor()

            for entry in feed.entries[:15]:
                source_url = entry.link.split('?')[0]  # 清理 URL 参数

                # 查重: 同时检查 source_url 或 doc_id (可选)
                cur.execute("SELECT id FROM financial_corpus WHERE source_url = %s", (source_url,))
                if cur.fetchone():
                    continue

                # 模拟人类行为延迟
                await asyncio.sleep(random.uniform(1.0, 3.0))

                article_resp = await client.get(source_url)
                # 使用 trafilatura 精准提取
                content = trafilatura.extract(article_resp.text, favor_precision=True)

                if content and len(content) > 300:
                    title = entry.title
                    ticker = extract_ticker(f"{title} {content[:200]}")

                    # --- 核心修改：适配新表结构 ---
                    doc_id = f"WEB_{uuid.uuid4().hex[:12].upper()}"  # 生成类似数据集的 ID
                    doc_type = 'news'
                    category = 'web_scraping'
                    dataset = 'Live-YahooFinance'
                    tags = ['RealTime', site_name]

                    # 简单的情感分析（演示用，可以接入模型）
                    sentiment_score = 0.0

                    # 向量化
                    text_to_embed = f"Title: {title}. Content: {content[:1000]}"
                    embedding = model.encode(text_to_embed).tolist()

                    # 插入新设计的表结构
                    cur.execute("""
                        INSERT INTO financial_corpus (
                            doc_id, title, content, ticker, 
                            source_type, category, dataset, 
                            trust_score, sensitivity_level, 
                            embedding, tags, source_url, 
                            published_at, sentiment_score
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (source_url) DO NOTHING
                    """, (
                        doc_id, title, content, ticker,
                        'public', category, dataset,
                        0.9, 0,  # trust_score 和 sensitivity_level
                        embedding, tags, source_url,
                        entry.get('published', datetime.now().isoformat()),
                        sentiment_score
                    ))

                    ingested_count += 1
                    print(f"  [+] Ingested: {title[:30]}... [{ticker}]")

            cur.execute("UPDATE crawling_source_configs SET last_scraped_at = NOW() WHERE id = %s", (source_id,))
            db_conn.commit()
            cur.close()
            return ingested_count

        except Exception as e:
            print(f"  [!] Failed {site_name}: {str(e)}")
            return 0


# --- 4. Main Entry (基本保持不变，确保连接正确) ---
async def main():
    conn = psycopg2.connect(
        host=db_cfg["host"],
        database=db_cfg["name"],
        user=db_cfg["user"],
        password=db_cfg["password"]
    )
    register_vector(conn)

    try:
        cur = conn.cursor()
        cur.execute("SELECT id, site_name, rss_url FROM crawling_source_configs WHERE is_active = TRUE")
        active_sources = cur.fetchall()
        cur.close()

        if not active_sources:
            print("No active crawling tasks found.")
            return

        tasks = [process_source(s, conn) for s in active_sources]
        results = await asyncio.gather(*tasks)
        print(f"[*] Crawler process completed. Total new records: {sum(results)}")
    finally:
        conn.close()


if __name__ == "__main__":
    asyncio.run(main())