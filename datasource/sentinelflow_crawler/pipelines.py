import yaml
import os
import datetime
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
            # 1. 自动生成 doc_id (如果 spider 没给)
            if not item.get('doc_id'):
                item['doc_id'] = f"WEB_{uuid.uuid4().hex[:12].upper()}"

            # 2. 生成 Embedding (标题 + 正文前段)
            text_for_embedding = f"{item['title']} {item['content'][:500]}"
            item['embedding'] = self.model.encode(text_for_embedding).tolist()

            # 3. 执行 SQL 插入
            sql = """
                INSERT INTO financial_corpus (
                    doc_id, title, content, ticker, source_type, 
                    category, dataset, trust_score, sensitivity_level, 
                    embedding, source_url, tags, published_at, 
                    sentiment_score, importance_rank
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (source_url) DO NOTHING;
            """
            self.cur.execute(sql, (
                item['doc_id'], item['title'], item['content'], item.get('ticker', 'GENERIC'),
                item.get('source_type', 'public'), item.get('category', 'news'),
                item.get('dataset', 'Scrapy-Yahoo'), item.get('trust_score', 0.9),
                item.get('sensitivity_level', 0), item['embedding'],
                item['source_url'], item.get('tags', []), item.get('published_at'),
                item.get('sentiment_score', 0.0), item.get('importance_rank', 5)
            ))
            self.conn.commit()
            return item

        except Exception as e:
            spider.logger.error(f"Error saving item: {e}")
            self.conn.rollback()
            return item

    def close_spider(self, spider):
        # 爬虫结束时，更新所有已激活源的最后爬取时间
        sql = "UPDATE crawling_source_configs SET last_scraped_at = %s WHERE is_active = TRUE"
        self.cur.execute(sql, (datetime.datetime.now(),))
        self.conn.commit()
        """爬虫结束时：关闭连接"""
        self.cur.close()
        self.conn.close()