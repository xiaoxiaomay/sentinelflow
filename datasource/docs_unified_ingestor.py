import os
import hashlib
import json
import pandas as pd
import fitz  # PyMuPDF
import psycopg2
import logging
from pgvector.psycopg2 import register_vector
from sentence_transformers import SentenceTransformer

# --- 引入: LangChain 切分器
from langchain_text_splitters import RecursiveCharacterTextSplitter

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

            # 初始化 LangChain 递归切分器
            # 它会按照 ["\n\n", "\n", "。", "！", "？", " ", ""] 的优先级递归切分
            self.text_splitter = RecursiveCharacterTextSplitter(
                chunk_size=self.embed_cfg.get("chunk_size", 800),  # 建议金融文本调大到 800-1000
                chunk_overlap=self.embed_cfg.get("chunk_overlap", 100),  # 增加重叠度以保持上下文
                length_function=len,
                is_separator_regex=False,
                # 按照语义强度从高到低排列
                separators=[
                    "\n\n",              # 1. 双换行（段落）
                    "\n",                # 2. 单换行（行）
                    "。 ",               # 3. 中文句号 + 空格（规整的中英混排）
                    "。",                # 4. 中文句号
                    ". ",                # 5. 英文句号 + 空格（核心：保护数字小数点）
                    "！", "!",           # 6. 感叹号（中英）
                    "？", "?",           # 7. 问号（中英）
                    "；", "; ",          # 8. 分号（中英，金融文档常用）
                    " ",                # 9. 空格（单词边界）
                    ""                  # 10. 字符级（保底方案）
                ]
            )

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
        # size = self.embed_cfg.get("chunk_size", 500)
        # overlap = self.embed_cfg.get("chunk_overlap", 50)
        # return [text[i: i + size] for i in range(0, len(text), size - overlap)] if text else []

        """使用LangChain 替代上面的 text[i:i+size] 逻辑"""
        if not text or not isinstance(text, str):
            return []
        # 返回的是切分后的字符串列表
        return self.text_splitter.split_text(text)

    def insert_to_db(self, item):
        """单条数据插入（不在这里 commit，由 process 函数统一控制事务）"""
        """插入逻辑（引入LangChain，增强了 doc_id的生成逻辑，防止 Chunk 冲突）"""
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
                embedding, 
                tags
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (doc_id) DO NOTHING
        """

        embedding = self.model.encode(item['content']).tolist()
        self.cur.execute(sql, (
            item['doc_id'],
            item['title'],
            item['content'],
            item.get('ticker', 'GENERIC'),
            item.get('source_type', 'internal'),
            item.get('category', 'document'),
            item.get('dataset', 'Internal-Upload'),
            1.0,
            embedding,
            item.get('tags', [])
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

            # 使用 LangChain 切分
            chunks = self.get_chunks(full_text)
            for i, chunk in enumerate(chunks):
                self.insert_to_db({
                    "doc_id": f"PDF_{file_hash}_C{i}",  # C stands for Chunk
                    "title": f"{file_name} (Chunk{i})",
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
            file_hash = hashlib.md5(file_name.encode()).hexdigest()[:8].upper()
            # 使用pandas分块读取，防止大文件撑爆内存
            reader = pd.read_csv(path, chunksize=500)

            for batch_idx, df_batch in enumerate(reader):
                for index, row in df_batch.iterrows():
                    actual_row_idx = batch_idx * 500 + index

                    # 提取主要内容字段
                    raw_content = str(row.get('content', ''))
                    title = row.get('title', f"{file_name} Row {actual_row_idx}")
                    ticker = row.get('ticker', 'GENERIC')

                    if not raw_content.strip():
                        continue

                    # --- 对 CSV 的列内容进行中英通用切分 ---
                    # 即使是一行数据，如果 content 字段超长，也会被切分成多个 Chunk
                    sub_chunks = self.get_chunks(raw_content)

                    for sub_idx, chunk in enumerate(sub_chunks):
                        # 构造唯一的 doc_id：文件名哈希 + 行号 + 子分片索引
                        doc_id = f"CSV_{file_hash}_R{actual_row_idx}_C{sub_idx}"

                        self.insert_to_db({
                            "doc_id": doc_id,
                            "title": f"{title} (Part {sub_idx})" if len(sub_chunks) > 1 else title,
                            "content": chunk,
                            "ticker": ticker,
                            "tags": [f"row_{actual_row_idx}"]  # 记录原始行号作为标签
                        })
                        count += 1

            self._update_task('SUCCESS', count)
            logger.info(f"Successfully processed CSV: {file_name}, generated {count} chunks.")
        except Exception as e:
            self._update_task('FAILED', count, str(e))
            logger.error(f"CSV Error {path}: {e}")

    def process_jsonl(self, path):
        """升级：即使是 JSONL 里的每一行，如果太长也要切分"""
        self._start_task(path)
        count = 0
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f):
                    data = json.loads(line)
                    raw_content = data.get('text') or data.get('content', "")
                    file_hash = hashlib.md5(path.encode()).hexdigest()[:6]

                    # 关键修改：对 JSONL 的每一条内容再做一次切分
                    sub_chunks = self.get_chunks(raw_content)
                    for sub_idx, chunk in enumerate(sub_chunks):
                        doc_id = f"JSL_{file_hash}_L{line_num}_C{sub_idx}"
                        self.insert_to_db({
                            "doc_id": doc_id,
                            "title": data.get('title', f"JSONL L{line_num} C{sub_idx}"),
                            "content": chunk,
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