from typing import List

from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from datasource.dao.interface.chat_history_dao import ChatHistoryDao
from datasource.models.chat_history import ChatHistory
from utils.logger_handler import logger

class ChatHistoryDaoImpl(ChatHistoryDao):
    def __init__(self, db_session: Session):
        self.db = db_session

    def get_messages_by_session(self, session_id: str):
        """
        获取该 session 的原始记录
        通常直接让 LangChain 处理，但管理后台可能需要此接口
        """
        return self.db.query(ChatHistory)\
            .filter(ChatHistory.session_id == session_id)\
            .order_by(ChatHistory.created_at.asc()).all()

    def get_user_session_list_with_titles(self, username: str, limit: int = 15) -> List[str]:
        """
        实现逻辑：
        1. 过滤指定 username 的所有记录
        2. 按 session_id 分组，并找出每个 session 的最后活跃时间 (MAX)
        3. 按最后活跃时间倒序排列，取出前 limit 个 session_id 和 title
        """
        try:
            # 找出每个 session 的最新活跃时间
            last_active_subquery = (
                self.db.query(
                    ChatHistory.session_id,
                    func.max(ChatHistory.created_at).label("last_active")
                )
                .filter(ChatHistory.username == username)
                .group_by(ChatHistory.session_id)
                .subquery()
            )
            # 标题子查询：找出每个 Session 里的非空标题
            # 即使对话有 100 条，我们也只取有标题的那一行
            title_subquery = (
                self.db.query(
                    ChatHistory.session_id,
                    func.max(ChatHistory.title).label("final_title") # 使用 max 取出非空的字符串
                )
                .filter(ChatHistory.username == username)
                .group_by(ChatHistory.session_id)
                .subquery()
            )
            
            # 主查询
            # 注意：同一个 session_id 的所有行的 title 理论上是相同的，我们取一条即可
            results = (
                self.db.query(
                    last_active_subquery.c.session_id,
                    title_subquery.c.final_title
                )
                .join(title_subquery, last_active_subquery.c.session_id == title_subquery.c.session_id)
                .order_by(desc(last_active_subquery.c.last_active))
                .limit(limit)
                .all()
            )
            
            # 返回列表，每个元素是一个字典或对象，方便前端读取
            # 格式: [{"id": "uuid...", "title": "总结标题"}, ...]
            return [{"id": row[0], "title": row[1]} for row in results]
        except Exception as e:
            logger.error(f"Failed to fetch sessions for user {username}: {e}")
            return []

    def delete_session(self, session_id: str) -> bool:
        """删除整个对话历史"""
        try:
            self.db.query(ChatHistory).filter(ChatHistory.session_id == session_id).delete()
            self.db.commit()
            return True
        except Exception as e:
            self.db.rollback()
            logger.error(f"Delete session failed: {e}")
            return False

    def count_messages(self, session_id: str) -> int:
        """统计消息数量，可用于 UI 显示 '共 X 条对话'"""
        return self.db.query(ChatHistory).filter(ChatHistory.session_id == session_id).count()
    
    def update_session_title(self, session_id: str, new_title: str):
        try:
            # 批量更新该 session_id 的所有记录标题
            # 反斜杠 (\) 的作用是 “行连接符”，让代码更清晰，告诉 Python 解释器：这一行还没有写完，下一行的内容属于这一行的一部分
            self.db.query(ChatHistory).filter(ChatHistory.session_id == session_id)\
                .update({"title": new_title}, synchronize_session=False)
            self.db.commit()
            return True
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error renaming session {session_id}: {e}")
            return False