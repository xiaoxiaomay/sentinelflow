
from sqlalchemy.orm import Session
from sqlalchemy import and_
from datasource.dao.interface.users_dao import UserDao
from datasource.models.users import User
from typing import Optional


class UserDaoImpl(UserDao):
    """DAO 实现层 - 处理具体数据库操作"""

    def __init__(self, session: Session):
        self.session = session

    def add(self, user: User):
        try:
            self.session.add(user)
            self.session.commit()
        except Exception as e:
            self.session.rollback()
            raise e

    def get_by_user_name(self, user_name: str) -> Optional[User]:
        return self.session.query(User).filter(and_(User.username == user_name, User.is_active)).first()

