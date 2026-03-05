from sqlalchemy import Column, Integer, String, Text, DateTime, func
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class IngestionTask(Base):
    """流水线任务表"""
    __tablename__ = 'ingestion_tasks'

    # 主键 ID，自增序列。唯一标识每一次入库任务。
    task_id = Column(Integer, primary_key=True, autoincrement=True)

    # 文件名（如 nvda_report.pdf）。方便人工查看和在前端展示数据来源。
    file_name = Column(Text, nullable=False)

    # 文件绝对路径（唯一约束）。1. 避免同一个路径的文件被重复创建任务。
    # 2. 方便程序定位原始物理文件。 3. UNIQUE 字段创建唯一索引，用于速查找和防重。
    file_path = Column(Text, unique=True, nullable=False)

    # 文件后缀/类型（PDF, CSV, JSONL）。用于统计不同格式数据的分布情况。
    file_type = Column(String(10), nullable=True)

    # 状态：'PROCESSING', 'SUCCESS', 'FAILED'
    status = Column(String(20), nullable=True)

    # 入库记录数。记录该文件最终拆分成了多少个片段（Chunks）存入 financial_corpus 表。
    record_count = Column(Integer, default=0)

    # 错误详细信息。当状态为 FAILED 时，记录 Python 抛出的 Exception 堆栈，方便快速定位。
    error_message = Column(Text, nullable=True)

    # 任务开始时间。默认当前时间。用于计算入库任务的排队情况。
    started_at = Column(DateTime, default=func.now())

    # 任务完成时间。与 started_at 相减可得出该文件的处理耗时，优化超大文件解析性能。
    completed_at = Column(DateTime, nullable=True)
    
    file_source_from = Column(String(30), nullable=True)  # 文件来源，如 'local_scan', 'web_upload', 'web_crawler'

