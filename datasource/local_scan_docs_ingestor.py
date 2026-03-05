import os
from utils.logger_handler import logger
from utils.db_conn_management import db_conn_manager
from datasource.dao.implementation.ingestion_tasks_dao_impl import IngestionTaskDaoImpl
from datasource.dao.implementation.financial_corpus_dao_impl import FinancialCorpusDaoImpl
from datasource.knowledge_base import KnowledgeBaseService
from sentence_transformers import SentenceTransformer
from langchain_text_splitters import RecursiveCharacterTextSplitter
from core.config_loader import get_engine_configs, get_project_root


class UnifiedIngestor:
    def __init__(self, kb_service: KnowledgeBaseService):
        """
        通过依赖注入获取 Service。
        Ingestor 不再关心如何切分、如何入库，只关心如何寻找文件。
        """
        self.kb_service = kb_service
        
        # 路径配置
        self.root = get_project_root()
        configs = get_engine_configs()
        self.path_cfg = configs.get("paths", {})

    def run(self):
        """
        扫描本地目录并处理文件
        """
        doc_dir = self.root / self.path_cfg.get("docs_dir", "datasource/docs")
        if not doc_dir.exists():
            logger.error(f"[*] Path not found: {doc_dir}")
            return

        logger.info(f"[*] Starting local directory scan: {doc_dir}")
        
        # 支持的文件后缀
        valid_extensions = {".pdf", ".csv", ".jsonl"}

        for file_path in doc_dir.iterdir():
            if file_path.suffix.lower() in valid_extensions:
                logger.info(f"[*] Found local file: {file_path.name}")
                try:
                    # 调用通用的 KnowledgeBaseService 处理逻辑
                    # source_from 标记为 'local_scan'，以区分 Web 上传
                    self.kb_service.handle_file(str(file_path), source_from='local_scan')
                except Exception as e:
                    # 单个文件失败不应阻塞整个目录的扫描
                    logger.error(f"[*] Failed to ingest {file_path.name}: {e}")
            else:
                logger.debug(f"[*] Skipping unsupported file type: {file_path.name}")

        logger.info("[*] All local ingestion tasks finished.")

if __name__ == "__main__":
    logger.info("=== SentinelFlow Local Ingestion Starter ===")
    
    # 1. 初始化数据库连接
    session = db_conn_manager.get_session()

    try:
        # 2. 准备基础组件 (DAO)
        financial_corpus_dao = FinancialCorpusDaoImpl(session)
        ingestion_task_dao = IngestionTaskDaoImpl(session)

        # 3. 准备 Service 所需的配置与模型
        configs = get_engine_configs()
        embed_cfg = configs.get("embedding", {})
        
        # 加载模型 (只需加载一次)
        logger.info(f"[*] Loading transformer model: {embed_cfg.get('model_name')}")
        model = SentenceTransformer(embed_cfg.get('model_name'))

        # 初始化切分器
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=embed_cfg.get("chunk_size", 800),
            chunk_overlap=embed_cfg.get("chunk_overlap", 100),
            length_function=len,
            separators=embed_cfg.get("separators")
        )

        # 4. 实例化核心 Service
        kb_service = KnowledgeBaseService(
            financial_corpus_dao=financial_corpus_dao,
            ingestion_task_dao=ingestion_task_dao,
            model=model,
            text_splitter=text_splitter
        )

        # 5. 启动 Ingestor
        ingestor = UnifiedIngestor(kb_service=kb_service)
        ingestor.run()

    except Exception as e:
        logger.error(f"Critical error during ingestion: {e}")
    finally:
        session.close()