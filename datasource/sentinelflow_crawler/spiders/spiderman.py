import os
import yaml
import datetime
import psycopg2
import scrapy
import feedparser
import trafilatura
import httpx
from ..items import FinancialArticleItem


class SpiderMan(scrapy.Spider):
    name = "spiderman"

    def __init__(self, *args, **kwargs):
        super(SpiderMan, self).__init__(*args, **kwargs)

        config = self.load_config()
        self.item_per_source = config.get('scraper', {}).get('item_per_source', 10)

        # 初始化一个统计字典
        self.crawl_stats = {}
        self.start_time = datetime.datetime.now()

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
                self.crawl_stats[site_name] = {"url": rss_url, "count": 0}
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

        # 初始化统计（如果还没初始化）
        if site_name not in self.crawl_stats:
            self.crawl_stats[site_name] = {'url': response.url, 'count': 0}

        feed = feedparser.parse(response.text)
        """
            Yahoo (同步阻塞控制)：
            Yahoo 使用的是 httpx.Client（同步请求）。
            这意味着当 parse 循环运行时，它必须等 fetch_with_httpx 执行完并返回结果，才会处理下一条。
            因此，一旦计数达到 10，循环立刻 break，控制非常精准。
        """
        """
            CNBC (异步并发控制)：
            CNBC 走的是 yield scrapy.Request。
            当你循环 RSS 列表时，Scrapy 瞬间就把这 30 条请求全部丢进了调度队列。
            等 Pipeline 里的数据库反馈“已存够 10 条”时，那剩下的 20 条请求已经发往 CNBC 服务器或者已经在下载路上了。
            Scrapy 不会自动撤回已经发出的请求，所以它们最终都会入库
        """
        for entry in feed.entries:

            # --- 第一重锁：检查当前已入库/已发出的总数 ---
            # 如果该源已处理的数量达到限额，直接停止解析该 RSS
            current_count = self.crawl_stats.get(site_name, {}).get('count', 0)
            if current_count >= self.item_per_source:
                self.logger.info(f"Source {site_name} reached quota ({self.item_per_source}), stopping.")
                break

            item = FinancialArticleItem()
            item['title'] = entry.title
            item['source_url'] = entry.link.split('?')[0]
            item['category'] = category
            item['dataset'] = site_name  # 记录来源

            # 策略：如果是 yahoo 域名，直接用 httpx 抓取正文
            if "finance.yahoo.com" in item['source_url']:
                # 注意：这里需要通过 yield 确保 item 流向 Pipeline
                result = self.fetch_with_httpx(item)
                if result:
                    # 只有在这里确认有产出，才增加计数
                    yield result
                    self.crawl_stats[site_name]['count'] += 1
            else:
                # --- 第二重锁：异步预计数 ---
                # 在发送 Request 之前，先占个位，防止瞬间发出过多请求
                self.crawl_stats[site_name]['count'] += 1
                # 其他源, 继续走 Scrapy 异步引擎 (parse_body 是异步的，计数建议移至 Pipeline)
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