from sqlalchemy import Column, Integer, String, Text, Float, DateTime, func, ForeignKey
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import declarative_base
from pgvector.sqlalchemy import Vector # 专门处理 pgvector

Base = declarative_base()


class FinancialCorpus(Base):
    __tablename__ = 'financial_corpus'

    # 1. 唯一标识符
    id = Column(Integer, primary_key=True, autoincrement=True)      # SERIAL PRIMARY KEY
    doc_id = Column(String(100), unique=True, nullable=False)       # 唯一约束

    # 2. 核心文本内容
    title = Column(Text, nullable=False)
    content = Column(Text, nullable=False)

    # 3. 金融属性
    ticker = Column(String(20), nullable=True)

    # 4. 来源与分类信息
    source_type = Column(String(50), nullable=True)
    category = Column(String(50), nullable=True)
    dataset = Column(String(100), nullable=True)

    # 5. 安全与质量指标
    trust_score = Column(Float, default=1.0)
    sensitivity_level = Column(Integer, default=0)

    # 6. 语义搜索核心 - 对应 384 维向量
    embedding = Column(Vector(384))

    # 7. 时间与自动记录
    published_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())                       # DEFAULT NOW()

    # 8. 爬虫兼容与扩展
    source_url = Column(Text, unique=True, nullable=True)
    tags = Column(ARRAY(String), nullable=True)                             # 对应 PostgreSQL 数组类型
    metadata_json = Column('metadata', JSONB, default={})        # 对应 JSONB

    # 9. 检索字段优化
    sentiment_score = Column(Float, default=0.0)
    importance_rank = Column(Integer, default=5)
    content_hash = Column(String(64), nullable=True)

    def __repr__(self):
        return f"<FinancialCorpus(doc_id='{self.doc_id}', title='{self.title[:20]}...')>"

