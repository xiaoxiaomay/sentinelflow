import yaml
import os
import datetime
import hashlib
import psycopg2
from pgvector.psycopg2 import register_vector
from sentence_transformers import SentenceTransformer
import uuid

# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html


# useful for handling different item types with a single interface
from itemadapter import ItemAdapter


class FinancialPipeline:

    def load_config(self):
        # 准确定位项目根目录下的 config.yaml
        current_script_dir = os.path.dirname(os.path.abspath(__file__))
        # 根据目录结构 需要向上跳两级
        base_dir = os.path.dirname(os.path.dirname(current_script_dir))
        config_path = os.path.join(base_dir, 'config.yaml')
        with open(config_path, 'r', encoding="utf-8") as f:
            return yaml.safe_load(f)

    def open_spider(self, spider):

        # 1. Load db configuration from config.yaml
        config = self.load_config()
        db_cfg = config['db']

        """爬虫启动时：初始化模型和数据库连接"""
        spider.logger.info("Initializing Embedding Model and DB connection...")
        self.model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')

        # 3. 传入解包后的参数
        try:
            self.conn = psycopg2.connect(
                host=db_cfg['host'],
                database=db_cfg['name'],  # 注意 yaml 里是 name，psycopg2 需要的是 database
                user=db_cfg['user'],
                password=db_cfg['password'],
                port=5432  # 如果 yaml 没写，默认 5432
            )
            register_vector(self.conn)
            self.cur = self.conn.cursor()
            spider.logger.info("远程数据库连接成功！(Host: %s)", db_cfg['host'])
        except Exception as e:
            spider.logger.error(f"数据库连接失败: {e}")
            raise e


    def process_item(self, item, spider):
        """每一条抓取到的数据都会经过这里"""
        try:
            # 2026-2-22-新增：生成内容指纹 (Content Hash)
            # 我们取正文的前 1000 个字符进行哈希，这样既能保证唯一性，又避开了末尾动态推荐内容的干扰
            content_str = item.get('content', '')
            if content_str:
                # 使用 SHA256 生成 64 位指纹
                item['content_hash'] = hashlib.sha256(content_str[:1000].encode('utf-8')).hexdigest()
            else:
                item['content_hash'] = None

            # 1. 自动生成 doc_id (如果 spider 没给)
            if not item.get('doc_id'):
                item['doc_id'] = f"WEB_{uuid.uuid4().hex[:12].upper()}"

            # 2. 生成 Embedding (标题 + 正文前段)
            text_for_embedding = f"{item['title']} {item['content'][:500]}"
            item['embedding'] = self.model.encode(text_for_embedding).tolist()

            # 3. 执行 SQL 插入
            sql = """
                INSERT INTO financial_corpus (
                    doc_id, 
                    title, 
                    content, 
                    ticker, 
                    source_type, 
                    category, 
                    dataset, 
                    trust_score, 
                    sensitivity_level, 
                    embedding, 
                    source_url, 
                    tags, 
                    published_at, 
                    sentiment_score, 
                    importance_rank, 
                    content_hash
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (source_url) DO NOTHING;
            """
            self.cur.execute(sql, (
                item['doc_id'],
                item['title'],
                item['content'],
                item.get('ticker', 'GENERIC'),
                item.get('source_type', 'public'),
                item.get('category', 'News'),
                item.get('dataset', 'Scrapy-Crawler'),
                item.get('trust_score', 0.9),
                item.get('sensitivity_level', 0),
                item['embedding'],
                item['source_url'],
                item.get('tags', []),
                item.get('published_at'),
                item.get('sentiment_score', 0.0),
                item.get('importance_rank', 5),
                item.get('content_hash', '')
            ))

            # -- 新增：如果插入成功（且不是因为冲突跳过），增加计数
            # rowcount > 0 表示真实插入了数据
            if self.cur.rowcount > 0:
                site_name = item.get('dataset')
                if hasattr(spider, 'crawl_stats') and site_name in spider.crawl_stats:
                    spider.crawl_stats[site_name]['count'] += 1

            self.conn.commit()
            return item

        except Exception as e:
            # 如果是因为 content_hash 导致的唯一约束冲突，这里会捕获到
            if "unique constraint" in str(e).lower():
                spider.logger.info(f"跳过重复内容: {item['title']}")
                self.conn.rollback()
            else:
                spider.logger.error(f"Error saving item: {e}")
                self.conn.rollback()
            return item

    def close_spider(self, spider):
        """爬虫结束时：更新配置表，并向ingestion_tasks写入每源统计"""
        try:
            # 1. 更新源配置表的最后爬取时间
            now = datetime.datetime.now()
            sql_update_config = "UPDATE crawling_source_configs SET last_scraped_at = %s WHERE is_active = TRUE"
            self.cur.execute(sql_update_config, (now,))

            # 2. 核心：将每个源的抓取数量写入 ingestion_tasks
            if hasattr(spider, 'crawl_stats'):
                for site_name, data in spider.crawl_stats.items():
                    # 纯插入模式，记录每一笔流水
                    sql_audit = """
                            INSERT INTO ingestion_tasks 
                            (
                            file_name, 
                            file_path, 
                            file_type, 
                            status, 
                            record_count, 
                            started_at, 
                            completed_at)
                            VALUES (%s, %s, %s, %s, %s, %s, %s);
                        """
                    self.cur.execute(sql_audit, (
                        f"Crawler: {site_name}",
                        data['url'],
                        'RSS',
                        'SUCCESS',
                        data['count'],
                        spider.start_time,
                        now
                    ))

            self.conn.commit()
            spider.logger.info("抓取信息已成功写入 ingestion_tasks 表")

        except Exception as e:
            spider.logger.error(f"关闭爬虫时更新ingestion_tasks表失败: {e}")
        finally:
            self.cur.close()
            self.conn.close()