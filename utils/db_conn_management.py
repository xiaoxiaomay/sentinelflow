from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from core.config_loader import get_db_params
from utils.logger_handler import logger


class DBConnManager:
    def __init__(self):
        # 1. 获取配置
        db_params = get_db_params()
        self.url = (f"postgresql://{db_params['user']}:"
                    f"{db_params['password']}@{db_params['host']}:{db_params['port']}/{db_params['database']}")

        # 2. 初始化引擎 (连接池)
        self.engine = create_engine(
            self.url,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True  # 这是一个好习惯，在连接空闲时检查是否存活
        )

        # 3. 创建 Session 工厂
        self.SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        logger.info("Database connection engine initialized.")

    def get_session(self) -> Session:
        """获取一个新的 session"""
        return self.SessionFactory()

    def close_all(self):
        """关闭引擎"""
        self.engine.dispose()
        logger.info("Database connection engine disposed.")


# 实例化一个全局的管理器实例
db_conn_manager = DBConnManager()

