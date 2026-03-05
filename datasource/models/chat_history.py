from sqlalchemy import Column, Integer, String, DateTime, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class ChatHistory(Base):
    """
    对话历史存储表
    专门用于持久化 LangChain 的聊天记录，支持基于 session_id 的快速检索
    """
    __tablename__ = 'chat_history'

    # 消息记录的唯一自增 ID
    id = Column(Integer, primary_key=True, autoincrement=True)

    # 会话 ID：格式为 uuid，用于隔离不同次对话
    # 建立索引以优化对话加载速度
    session_id = Column(String(255), nullable=False, index=True)
    
    # 对话摘要
    title = Column(String(255), nullable=True)
    
    # 用户名
    username = Column(String(100), nullable=True, index=True)

    # 消息核心内容：存储为 JSONB 格式
    # 包含消息类型(human/ai)和内容(content)，由 LangChain 自动序列化
    message = Column(JSONB, nullable=False)

    # 记录创建时间：自动记录消息入库时间，用于前端按时间轴排序
    created_at = Column(DateTime, server_default=func.now())