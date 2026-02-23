# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class FinancialArticleItem(scrapy.Item):
    # 唯一标识与去重
    doc_id = scrapy.Field()
    source_url = scrapy.Field()

    # 内容核心
    title = scrapy.Field()
    content = scrapy.Field()
    content_hash = scrapy.Field()
    ticker = scrapy.Field()

    # 来源分类
    source_type = scrapy.Field()
    category = scrapy.Field()
    dataset = scrapy.Field()

    # 质量与安全
    trust_score = scrapy.Field()
    sensitivity_level = scrapy.Field()

    # AI 增强字段
    embedding = scrapy.Field()
    sentiment_score = scrapy.Field()
    importance_rank = scrapy.Field()

    # 时间与元数据
    published_at = scrapy.Field()
    tags = scrapy.Field()
    metadata = scrapy.Field()
