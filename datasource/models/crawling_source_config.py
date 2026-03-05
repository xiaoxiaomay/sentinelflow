from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class CrawlingSourceConfig(Base):
    """爬虫配置表"""
    __tablename__ = 'crawling_source_configs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    site_name = Column(String(100), nullable=True)
    rss_url = Column(Text, nullable=True)
    category = Column(String(50), nullable=True)
    is_active = Column(Boolean, default=True)
    last_scraped_at = Column(DateTime, nullable=True)

    # 爬取间隔（分钟），用于自动调度任务
    refresh_interval_min = Column(Integer, default=30)


