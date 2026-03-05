from abc import ABC, abstractmethod
from typing import Optional
from datasource.models.ingestion_tasks import IngestionTask


class IngestionTaskDao(ABC):
    """DAO 接口层 - 定义数据操作规范"""

    @abstractmethod
    def add(self, task: IngestionTask) -> int:
        """插入单条记录"""
        pass

    @abstractmethod
    def get_task_by_task_id(self, task_id: int) -> Optional[IngestionTask]:
        """根据 task_id 查询"""
        pass

    @abstractmethod
    def check_exists_by_path(self, file_path: str) -> bool:
        """检查文件路径是否已存在任务"""
        pass

    @abstractmethod
    def update_task_by_task_id(self, task_id: int, status: str, record_count: int = None, error_message: str = None) -> bool:
        pass

