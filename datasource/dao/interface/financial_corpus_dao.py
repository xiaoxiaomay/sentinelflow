from abc import ABC, abstractmethod
from typing import Optional
from datasource.models.financial_corpus import FinancialCorpus


class FinancialCorpusDao(ABC):
    """DAO 接口层 - 定义数据操作规范"""

    @abstractmethod
    def add(self, corpus: FinancialCorpus):
        """插入单条记录"""
        pass

    @abstractmethod
    def get_by_doc_id(self, doc_id: str) -> Optional[FinancialCorpus]:
        """根据 doc_id 查询"""
        pass

