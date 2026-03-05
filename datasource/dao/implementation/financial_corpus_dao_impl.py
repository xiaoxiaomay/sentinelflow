from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert  # PostgreSQL 特有导入
from datasource.dao.interface.financial_corpus_dao import FinancialCorpusDao
from datasource.models.financial_corpus import FinancialCorpus
from typing import Optional
from utils.logger_handler import logger


class FinancialCorpusDaoImpl(FinancialCorpusDao):
    """DAO 实现层 - 处理具体数据库操作"""

    def __init__(self, session: Session):
        self.session = session

    def add(self, corpus: FinancialCorpus):
        return self._insert_ignoring_conflicts(corpus)

    def get_by_doc_id(self, doc_id: str) -> Optional[FinancialCorpus]:
        return self.session.query(FinancialCorpus).filter(FinancialCorpus.doc_id == doc_id).first()

    def _insert_ignoring_conflicts(self, corpus: FinancialCorpus):
        """
        内部方法：处理 SQLAlchemy ORM 对象到字典的转换，并执行带冲突忽略的插入。
        """
        try:
            # 1. 将 ORM 对象映射为字典
            # 这里使用了 SQLAlchemy 的 instance_state 来获取所有属性
            values = {
                "doc_id": corpus.doc_id,
                "title": corpus.title,
                "content": corpus.content,
                "ticker": corpus.ticker,
                "source_type": corpus.source_type,
                "category": corpus.category,
                "dataset": corpus.dataset,
                "trust_score": corpus.trust_score,
                "embedding": corpus.embedding,
                "tags": corpus.tags,
                "content_hash": corpus.content_hash
            }

            # 2. 构建 PostgreSQL 的 INSERT ... ON CONFLICT DO NOTHING 语句
            stmt = insert(FinancialCorpus).values(**values).on_conflict_do_nothing(
                index_elements=['doc_id']  # 必须是表中唯一的字段名
            )

            # 3. 执行
            result = self.session.execute(stmt)
            self.session.commit()

            # 4. rowcount 返回的是数据库实际受影响的行数
            # 如果冲突了，rowcount 是 0；如果插入成功，rowcount 是 1
            rowcount = result.rowcount
            if rowcount == 1:
                logger.info(f"Insert doc_id: {corpus.doc_id}")
            if rowcount == 0:
                logger.info(f"Skip or fail to insert doc_id: {corpus.doc_id}")
            return result.rowcount

        except Exception as e:
            # 4. 出现除冲突外的其他错误时回滚
            self.session.rollback()
            logger.error(f"Error inserting corpus {corpus.doc_id}: {e}")
            raise e

