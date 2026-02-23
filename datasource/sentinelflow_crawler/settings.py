import sys
from pathlib import Path

# --- 路径补丁：确保能找到根目录下的 core 模块 ---
# 获取当前 settings.py 的上两级目录（即项目根目录）
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

# --- 导入配置 ---
try:
    from core.config_loader import load_global_config
    cfg = load_global_config()
    scraper_cfg = cfg.get('scraper', {})
except Exception as e:
    print(f"[*] Warning: Could not load config.yaml, using defaults. Error: {e}")
    scraper_cfg = {}

# Scrapy settings for sentinelflow_crawler project
#
# For simplicity, this file contains only settings considered important or
# commonly used. You can find more settings consulting the documentation:
#
#     https://docs.scrapy.org/en/latest/topics/settings.html
#     https://docs.scrapy.org/en/latest/topics/downloader-middleware.html
#     https://docs.scrapy.org/en/latest/topics/spider-middleware.html

BOT_NAME = "sentinelflow_crawler"

SPIDER_MODULES = ["sentinelflow_crawler.spiders"]
NEWSPIDER_MODULE = "sentinelflow_crawler.spiders"

ADDONS = {}

# 核心修复：禁用引起 ValueError 的中间件
DOWNLOADER_MIDDLEWARES = {
    'scrapy.downloadermiddlewares.cookies.CookiesMiddleware': None,
    'scrapy.downloadermiddlewares.redirect.RedirectMiddleware': None,
}


# Crawl responsibly by identifying yourself (and your website) on the user-agent
#USER_AGENT = "sentinelflow_crawler (+http://www.yourdomain.com)"

# Obey robots.txt rules
# ROBOTSTXT_OBEY = False

# Concurrency and throttling settings
#CONCURRENT_REQUESTS = 16
CONCURRENT_REQUESTS_PER_DOMAIN = 1
#DOWNLOAD_DELAY = 1

# 遵守爬虫礼仪（Yahoo 对并发很敏感）
ROBOTSTXT_OBEY = False
CONCURRENT_REQUESTS = 4
DOWNLOAD_DELAY = 3
RANDOMIZE_DOWNLOAD_DELAY = True

# Disable cookies (enabled by default)
#COOKIES_ENABLED = False

# Disable Telnet Console (enabled by default)
#TELNETCONSOLE_ENABLED = False

# Override the default request headers:
#DEFAULT_REQUEST_HEADERS = {
#    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
#    "Accept-Language": "en",
#}

# Enable or disable spider middlewares
# See https://docs.scrapy.org/en/latest/topics/spider-middleware.html
#SPIDER_MIDDLEWARES = {
#    "sentinelflow_crawler.middlewares.SentinelflowCrawlerSpiderMiddleware": 543,
#}

# Enable or disable downloader middlewares
# See https://docs.scrapy.org/en/latest/topics/downloader-middleware.html
#DOWNLOADER_MIDDLEWARES = {
#    "sentinelflow_crawler.middlewares.SentinelflowCrawlerDownloaderMiddleware": 543,
#}

# Enable or disable extensions
# See https://docs.scrapy.org/en/latest/topics/extensions.html
#EXTENSIONS = {
#    "scrapy.extensions.telnet.TelnetConsole": None,
#}

# Configure item pipelines
# See https://docs.scrapy.org/en/latest/topics/item-pipeline.html
#ITEM_PIPELINES = {
#    "sentinelflow_crawler.pipelines.SentinelflowCrawlerPipeline": 300,
#}

# Enable and configure the AutoThrottle extension (disabled by default)
# See https://docs.scrapy.org/en/latest/topics/autothrottle.html
#AUTOTHROTTLE_ENABLED = True
# The initial download delay
#AUTOTHROTTLE_START_DELAY = 5
# The maximum download delay to be set in case of high latencies
#AUTOTHROTTLE_MAX_DELAY = 60
# The average number of requests Scrapy should be sending in parallel to
# each remote server
#AUTOTHROTTLE_TARGET_CONCURRENCY = 1.0
# Enable showing throttling stats for every response received:
#AUTOTHROTTLE_DEBUG = False

# Enable and configure HTTP caching (disabled by default)
# See https://docs.scrapy.org/en/latest/topics/downloader-middleware.html#httpcache-middleware-settings
#HTTPCACHE_ENABLED = True
#HTTPCACHE_EXPIRATION_SECS = 0
#HTTPCACHE_DIR = "httpcache"
#HTTPCACHE_IGNORE_HTTP_CODES = []
#HTTPCACHE_STORAGE = "scrapy.extensions.httpcache.FilesystemCacheStorage"

# Set settings whose default value is deprecated to a future-proof value
FEED_EXPORT_ENCODING = "utf-8"

# 模拟真实浏览器
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

# 开启数据流水线
ITEM_PIPELINES = {
    'sentinelflow_crawler.pipelines.FinancialPipeline': 300,
}

# --- 动态赋值 ---

# 1. 抓取限额：达到数目后自动关闭蜘蛛
# Scrapy 内置扩展：CloseSpider
# CLOSESPIDER_ITEMCOUNT = scraper_cfg.get('item_limit', 20)  # 为了让每个抓取源都能获的资源，不再使用scrapy的全局控制

# 2. 并发设置
CONCURRENT_REQUESTS = scraper_cfg.get('concurrent_requests', 10)

# --- 其他建议配置 ---
# 为了配合 CloseSpider，通常需要确保扩展是开启的（默认是开启的）
EXTENSIONS = {
    'scrapy.extensions.closespider.CloseSpider': 500,
}