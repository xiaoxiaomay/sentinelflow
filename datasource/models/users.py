from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, func
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class User(Base):
    """用户鉴权表"""
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False)

    # 存储 bcrypt 哈希后的密码，绝不存明文
    password_hash = Column(Text, nullable=False)
    email = Column(String(100), unique=True, nullable=True)

    # 角色：admin, user, guest
    role = Column(String(20), default='user')

    # 用户API调用剩余点数，用于限流和变现
    api_quota_remaining = Column(Integer, default=100)

    is_active = Column(Boolean, default=True)
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())