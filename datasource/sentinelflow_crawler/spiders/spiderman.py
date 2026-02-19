import os
import yaml
import psycopg2
import scrapy
import feedparser
import trafilatura
import httpx
from ..items import FinancialArticleItem


class SpiderMan(scrapy.Spider):
    name = "spiderman"

    def load_config(self):
        # 准确定位项目根目录下的 config.yaml
        current_script_dir = os.path.dirname(os.path.abspath(__file__))
        # 根据目录结构 需要向上跳三级
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(current_script_dir)))
        config_path = os.path.join(base_dir, 'config.yaml')
        with open(config_path, 'r', encoding="utf-8") as f:
            return yaml.safe_load(f)


    def start_requests(self):
        """重写此方法，实现动态任务加载"""
        config = self.load_config()
        db_cfg = config['db']

        try:
            conn = psycopg2.connect(
                host=db_cfg['host'],
                database=db_cfg['name'],  # 注意 yaml 里是 name，psycopg2 需要的是 database
                user=db_cfg['user'],
                password=db_cfg['password'],
                port=5432  # 如果 yaml 没写，默认 5432
            )
            cur = conn.cursor()
            # 获取所有激活的任务
            cur.execute("SELECT site_name, rss_url, category FROM crawling_source_configs WHERE is_active = TRUE")
            missions = cur.fetchall()
            cur.close()
            conn.close()

            if not missions:
                self.logger.warning("No active missions found in database!")
                return

            for site_name, rss_url, category in missions:
                self.logger.info(f"Starting mission: {site_name} -> {rss_url}")
                yield scrapy.Request(
                    url=rss_url,
                    callback=self.parse,
                    meta={'site_name': site_name, 'category': category},
                    dont_filter=True  # RSS 源通常需要重复访问
                )
        except Exception as e:
            self.logger.error(f"Failed to load missions from DB: {e}")

    def parse(self, response):

        site_name = response.meta.get('site_name')
        category = response.meta.get('category')

        feed = feedparser.parse(response.text)

        for entry in feed.entries[:2]:     # limited by 2
            item = FinancialArticleItem()
            item['title'] = entry.title
            item['source_url'] = entry.link.split('?')[0]
            item['category'] = category
            item['dataset'] = site_name  # 记录来源

            # 策略：如果是 yahoo 域名，直接用 httpx 抓取正文
            if "finance.yahoo.com" in item['source_url']:
                yield self.fetch_with_httpx(item)
            else:
                # 其他源（如 Investors.com）继续走 Scrapy 异步引擎
                yield scrapy.Request(item['source_url'], callback=self.parse_body, meta={'item': item})

    def fetch_with_httpx(self, item):
        self.logger.info(f"Employing HTTPX to crawl Yahoo pages: {item['title']}")
        try:
            with httpx.Client(timeout=15.0, follow_redirects=True) as client:
                resp = client.get(item['source_url'], headers={
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Referer': 'https://www.google.com/',  # 伪造搜索来源
                    'DNT': '1',
                })
                content = trafilatura.extract(resp.text)
                if content:
                    item['content'] = content
                    # 直接返回 item 触发 Pipeline 入库
                    return item
        except Exception as e:
            self.logger.error(f"HTTPX 抓取失败: {e}")

    def parse_body(self, response):
        item = response.meta['item']
        content = trafilatura.extract(response.text)
        if content:
            item['content'] = content
            yield item