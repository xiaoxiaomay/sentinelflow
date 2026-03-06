from abc import ABC, abstractmethod
from typing import List, Optional
from langchain_core.messages import BaseMessage

class ChatHistoryDao(ABC):
    @abstractmethod
    def get_messages_by_session(self, session_id: str) -> List[BaseMessage]:
        """获取指定会话的所有消息"""
        pass

    @abstractmethod
    def get_user_session_list_with_titles(self, username: str, limit: int = 15) -> List[str]:
        """
        根据用户名获取该用户最近的会话 ID 列表。
        不再依赖 session_id 的字符串前缀，而是直接通过字段过滤。
        """
        pass

    @abstractmethod
    def delete_session(self, session_id: str) -> bool:
        """删除某个会话及其所有记录"""
        pass
    
    @abstractmethod
    def count_messages(self, session_id: str) -> int:
        """统计某个会话的消息条数"""
        pass
    
    @abstractmethod
    def update_session_title(self, session_id: str, title: str) -> bool:
        """更新某个会话的标题"""
        pass