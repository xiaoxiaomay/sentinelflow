import os
import hashlib
import json
import pandas as pd
import fitz  # PyMuPDF
import psycopg2
import logging
from pgvector.psycopg2 import register_vector
from sentence_transformers import SentenceTransformer

# 导入配置加载器
from core.config_loader import get_db_params, get_engine_configs, get_project_root

# 配置日志，方便排查无法读取的文件
root = get_project_root()
log_dir = root / "data/ingestion"
log_file_path = log_dir / "ingestion.log"

# 自动创建不存在的目录层级
# parents=True 表示递归创建目录，exist_ok=True 表示如果目录已存在则不报错
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file_path, encoding='utf-8'), # 写入文件
        logging.StreamHandler() # 同时在屏幕输出
    ]
)
logger = logging.getLogger(__name__)


class UnifiedIngestor:
    def __init__(self):
        try:
            self.root = get_project_root()
            configs = get_engine_configs()
            self.embed_cfg = configs.get("embedding", {})
            self.path_cfg = configs.get("paths", {})

            # 初始化模型
            logger.info(f"[*] Loading model: {self.embed_cfg.get('model_name')}")
            self.model = SentenceTransformer(self.embed_cfg.get('model_name'))

            # 连接数据库
            db_params = get_db_params()
            self.conn = psycopg2.connect(**db_params)
            register_vector(self.conn)
            self.cur = self.conn.cursor()

            self.current_task_id = None
        except Exception as e:
            logger.error(f"Initialization error: {e}")
            raise

    # --- 任务追踪逻辑 ---
    def _start_task(self, path):
        """记录任务开始"""
        sql = """
            INSERT INTO ingestion_tasks (file_name, file_path, file_type, status, started_at)
            VALUES (%s, %s, %s, 'PROCESSING', CURRENT_TIMESTAMP)
            RETURNING task_id;
        """
        file_name = os.path.basename(path)
        check_sql = "SELECT 1 FROM ingestion_tasks WHERE file_name = %s LIMIT 1;"
        self.cur.execute(check_sql, (file_name,))
        if self.cur.fetchone():
            print(f"Skip: {file_name}'s content already exists in financial_corpus.")
            return None  # 或者标记任务为 SKIPPED

        file_type = os.path.splitext(path)[1].replace('.', '').upper()
        self.cur.execute(sql, (file_name, path, file_type))
        self.current_task_id = self.cur.fetchone()[0]
        self.conn.commit()

    def _update_task(self, status, count=0, error=None):
        """记录任务结束或失败"""
        if self.current_task_id:
            sql = """
                UPDATE ingestion_tasks 
                SET status = %s, record_count = %s, error_message = %s, completed_at = CURRENT_TIMESTAMP
                WHERE task_id = %s
            """
            self.cur.execute(sql, (status, count, error, self.current_task_id))
            self.conn.commit()

    # --- 核心逻辑 ---
    def get_chunks(self, text):
        size = self.embed_cfg.get("chunk_size", 500)
        overlap = self.embed_cfg.get("chunk_overlap", 50)
        return [text[i: i + size] for i in range(0, len(text), size - overlap)] if text else []

    def insert_to_db(self, item):
        """单条数据插入（不在这里 commit，由 process 函数统一控制事务）"""
        sql = """
            INSERT INTO financial_corpus (
                doc_id, title, content, ticker, source_type, 
                category, dataset, trust_score, embedding, tags
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (doc_id) DO NOTHING
        """
        embedding = self.model.encode(item['content']).tolist()
        self.cur.execute(sql, (
            item['doc_id'], item['title'], item['content'],
            item.get('ticker', 'GENERIC'), 'internal',
            item.get('category', 'document'), 'Internal-Upload',
            1.0, embedding, item.get('tags', [])
        ))

    def process_pdf(self, path):
        self._start_task(path)
        count = 0
        try:
            file_name = os.path.basename(path)
            file_hash = hashlib.md5(file_name.encode()).hexdigest()[:10].upper()
            doc = fitz.open(path)
            full_text = "".join([page.get_text() for page in doc])
            doc.close()

            chunks = self.get_chunks(full_text)
            for i, chunk in enumerate(chunks):
                self.insert_to_db({
                    "doc_id": f"PDF_{file_hash}_P{i}",
                    "title": f"{file_name} (P{i + 1})",
                    "content": chunk
                })
                count += 1
            self._update_task('SUCCESS', count)
        except Exception as e:
            self._update_task('FAILED', count, str(e))
            logger.error(f"PDF Error {path}: {e}")

    def process_csv(self, path):
        self._start_task(path)
        count = 0
        try:
            file_name = os.path.basename(path)
            file_hash = hashlib.md5(file_name.encode()).hexdigest()[:10].upper()
            reader = pd.read_csv(path, chunksize=500)
            for chunk_idx, chunk in enumerate(reader):
                for index, row in chunk.iterrows():
                    actual_idx = chunk_idx * 500 + index
                    self.insert_to_db({
                        "doc_id": f"CSV_{file_hash}_{actual_idx}",
                        "title": row.get('title', f"{file_name} Row {actual_idx}"),
                        "content": row.get('content', str(row.to_dict())),
                        "ticker": row.get('ticker', 'GENERIC')
                    })
                    count += 1
            self._update_task('SUCCESS', count)
        except Exception as e:
            self._update_task('FAILED', count, str(e))
            logger.error(f"CSV Error {path}: {e}")

    def process_jsonl(self, path):
        self._start_task(path)
        count = 0
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f):
                    data = json.loads(line)
                    doc_id = data.get('_id') or f"JSL_{hashlib.md5(line.encode()).hexdigest()[:10]}_{line_num}"
                    content = data.get('text') or data.get('content', "")
                    self.insert_to_db({
                        "doc_id": doc_id,
                        "title": data.get('title', f"JSONL Item {line_num}"),
                        "content": content,
                        "ticker": data.get('ticker', 'GENERIC')
                    })
                    count += 1
            self._update_task('SUCCESS', count)
        except Exception as e:
            self._update_task('FAILED', count, str(e))
            logger.error(f"JSONL Error {path}: {e}")

    def run(self):
        doc_dir = self.root / self.path_cfg.get("docs_dir", "datasource/docs")
        if not doc_dir.exists():
            logger.error(f"Path not found: {doc_dir}")
            return

        for file_path in doc_dir.iterdir():
            ext = file_path.suffix.lower()
            if ext == ".pdf":
                self.process_pdf(str(file_path))
            elif ext == ".csv":
                self.process_csv(str(file_path))
            elif ext == ".jsonl":
                self.process_jsonl(str(file_path))

        self.cur.close()
        self.conn.close()
        logger.info("[*] All tasks finished.")


if __name__ == "__main__":
    UnifiedIngestor().run()