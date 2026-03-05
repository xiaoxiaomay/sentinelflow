from abc import ABC, abstractmethod
from typing import Optional
from datasource.models.users import User


class UserDao(ABC):
    """DAO 接口层 - 定义数据操作规范"""

    @abstractmethod
    def add(self, user: User):
        """插入单条记录"""
        pass

    @abstractmethod
    def get_by_user_name(self, user_name: str) -> Optional[User]:
        """根据 user_name 查询"""
        pass

