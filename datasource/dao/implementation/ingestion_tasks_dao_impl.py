
from sqlalchemy.orm import Session
from datasource.dao.interface.ingestion_tasks_dao import IngestionTaskDao
from datasource.models.ingestion_tasks import IngestionTask
from typing import Optional
from sqlalchemy import func


class IngestionTaskDaoImpl(IngestionTaskDao):
    """DAO 实现层 - 处理具体数据库操作"""

    def __init__(self, session: Session):
        self.session = session

    def add(self, task: IngestionTask):
        try:
            self.session.add(task)
            self.session.commit()
            # 关键点：commit 后，SQLAlchemy 会自动将数据库生成的主键 ID 赋值给对象
            return task.task_id
        except Exception as e:
            self.session.rollback()
            raise e

    def get_task_by_task_id(self, task_id: int) -> Optional[IngestionTask]:
        return self.session.query(IngestionTask).filter(IngestionTask.task_id == task_id).first()

    def check_exists_by_path(self, file_path: str) -> bool:
        """检查文件路径是否已存在任务"""
        return self.session.query(IngestionTask).filter(IngestionTask.file_path == file_path).first() is not None

    def update_task_by_task_id(self, task_id: int, status: str, record_count: int = None, error_message: str = None) -> bool:
        """
        根据 task_id 更新任务状态及相关信息
        :return: 是否更新成功
        """
        try:
            # 1. 查询需要更新的任务
            task = self.session.query(IngestionTask).filter(IngestionTask.task_id == task_id).first()

            if not task:
                return False

            # 2. 更新字段
            task.status = status

            if record_count is not None:
                task.record_count = record_count
            if error_message is not None:
                task.error_message = error_message

            # 如果状态变更为最终状态，通常也会更新完成时间 (建议在模型或DAO中处理)
            if status in ['SUCCESS', 'FAILED']:
                task.completed_at = func.now()

            # 3. 提交事务
            self.session.commit()
            return True

        except Exception as e:
            # 4. 回滚事务
            self.session.rollback()
            # 在这里记录日志
            # logger.error(f"Failed to update task {task_id}: {e}")
            raise e

