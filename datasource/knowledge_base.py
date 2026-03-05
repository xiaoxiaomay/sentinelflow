import os
import hashlib
import json
import pandas as pd
from utils.logger_handler import logger
from datasource.models.financial_corpus import FinancialCorpus
from datasource.models.ingestion_tasks import IngestionTask
from langchain_community.document_loaders import PyPDFLoader
from langchain_core.documents import Document

class KnowledgeBaseService:
    def __init__(self, financial_corpus_dao, ingestion_task_dao, model, text_splitter):
        self.financial_corpus_dao = financial_corpus_dao
        self.ingestion_task_dao = ingestion_task_dao
        self.model = model
        self.text_splitter = text_splitter

    def _get_filename_md5(self, file_name):
        """仅针对文件名生成 MD5，用于构造 doc_id 的前缀"""
        return hashlib.md5(file_name.encode()).hexdigest()[:10].upper()

    def handle_file(self, file_path, source_from='local_scan'):
        """
        统一处理入口
        :param file_path: 文件的绝对路径
        :param source_from: 来源 ('local_scan' 或 'web_upload')
        """
        file_name = os.path.basename(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # 针对文件名生成的指纹，用于 doc_id
        name_fingerprint = self._get_filename_md5(file_name)

        # 1. 开启任务追踪 (此处不进行内容校验，只记录文件处理行为)
        task = IngestionTask(
            file_name=file_name,
            file_path=file_path,
            file_type=file_ext.replace('.', '').upper(),
            status='PROCESSING',
            file_source_from=source_from
        )
        task_id = self.ingestion_task_dao.add(task)
        
        count = 0
        try:
            # 2. 分流处理
            if file_ext == ".pdf":
                count = self._process_pdf(file_path, file_name, name_fingerprint)
            elif file_ext == ".csv":
                count = self._process_csv(file_path, file_name, name_fingerprint)
            elif file_ext == ".jsonl":
                count = self._process_jsonl(file_path, name_fingerprint)
            
            # 3. 更新任务结果
            self.ingestion_task_dao.update_task_by_task_id(task_id, 'SUCCESS', count)
            logger.info(f"[+] File: {file_name} processed. {count} chunks upserted.")
            return count

        except Exception as e:
            self.ingestion_task_dao.update_task_by_task_id(task_id, 'FAILED', count, str(e))
            logger.error(f"[!] Failed to process {file_name}: {e}")
            raise e

    def _insert_to_db(self, item):
        """
        核心入库逻辑
        使用 SHA-256 对 content 进行哈希校验，防止相同文本重复入库
        """
        content_str = item.get('content', '')
        # 对内容前 1000 字进行 SHA-256 哈希，用于数据库唯一性校验
        c_hash = hashlib.sha256(content_str[:1000].encode('utf-8')).hexdigest()
        
        corpus = FinancialCorpus(
            doc_id=item['doc_id'],
            title=item['title'],
            content=content_str,
            ticker=item.get('ticker', 'GENERIC'),
            source_type=item.get('source_type', 'internal'),
            category=item.get('category', 'document'),
            dataset=item.get('dataset', 'Internal-Upload'),
            trust_score=1.0,
            embedding=self.model.encode(content_str).tolist(),
            tags=item.get('tags', []),
            content_hash=c_hash  # 真正的去重逻辑在这里
        )
        
        # 调用 DAO，DAO 层应处理 ON CONFLICT (content_hash) DO NOTHING
        return self.financial_corpus_dao.add(corpus)

    def _process_pdf(self, path, file_name, name_md5):
        count = 0
        loader = PyPDFLoader(path)
        docs = loader.load()
        chunks = self.text_splitter.split_documents(docs)
        
        for i, chunk in enumerate(chunks):
            data = {
                # 使用文件名 MD5 构造 doc_id，保证同一个文件生成的 ID 有规律
                "doc_id": f"PDF_{name_md5}_C{i}",
                "title": f"{file_name} (Page {chunk.metadata.get('page', 0)+1})",
                "content": chunk.page_content,
                "tags": [f"page_{chunk.metadata.get('page', 0)}"]
            }
            count += self._insert_to_db(data)
        return count

    def _process_csv(self, path, file_name, name_md5):
        count = 0
        reader = pd.read_csv(path, chunksize=500)
        for batch_idx, df_batch in enumerate(reader):
            for index, row in df_batch.iterrows():
                actual_idx = batch_idx * 500 + index
                raw_content = str(row.get('content', ''))
                if not raw_content.strip(): continue
                
                sub_chunks = self.text_splitter.split_text(raw_content)
                for s_idx, chunk in enumerate(sub_chunks):
                    data = {
                        "doc_id": f"CSV_{name_md5}_R{actual_idx}_C{s_idx}",
                        "title": row.get('title', f"{file_name}_R{actual_idx}"),
                        "content": chunk,
                        "ticker": row.get('ticker', 'GENERIC')
                    }
                    count += self._insert_to_db(data)
        return count

    def _process_jsonl(self, path, name_md5):
        count = 0
        with open(path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f):
                item = json.loads(line)
                raw_content = item.get('text') or item.get('content', "")
                if not raw_content: continue
                
                sub_chunks = self.text_splitter.split_text(raw_content)
                for s_idx, chunk in enumerate(sub_chunks):
                    data = {
                        "doc_id": f"JSL_{name_md5}_L{line_num}_C{s_idx}",
                        "title": item.get('title', f"JSONL_L{line_num}"),
                        "content": chunk,
                        "ticker": item.get('ticker', 'GENERIC')
                    }
                    count += self._insert_to_db(data)
        return count