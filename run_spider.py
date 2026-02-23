import os
import sys
from pathlib import Path

# 1. 准确定位 datasource 文件夹的路径
# Path(__file__).resolve().parent 得到 run_spider.py 所在的目录
# 然后拼接上 'datasource'
BASE_DIR = Path(__file__).resolve().parent / "datasource"

# 2. 将 datasource 及其子目录加入搜索路径
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

# 3. 设置 Scrapy 设置模块的环境变量
# 注意：由于 datasource 已在路径中，Python 可以直接找到 sentinelflow_crawler
os.environ.setdefault('SCRAPY_SETTINGS_MODULE', 'sentinelflow_crawler.settings')

# 4. 导入 Scrapy 组件了
from scrapy.crawler import CrawlerProcess
from scrapy.utils.project import get_project_settings


def main():
    try:
        # 加载设置
        settings = get_project_settings()

        # 验证是否成功加载了 settings.py
        if not settings.get('BOT_NAME'):
            raise ImportError("Cannot find Scrapy settings. Check if 'datasource' path is correct.")

        process = CrawlerProcess(settings)

        print(f"[Master] Starting SpiderMan...")
        print(f"[Path] Project Base: {BASE_DIR}")

        process.crawl('spiderman')
        process.start()

    except Exception as e:
        print(f"Initialization Error: {e}")


if __name__ == "__main__":
    main()