import streamlit as st
import json
import psycopg2
import psycopg
import yaml
import os
from dotenv import load_dotenv
import bcrypt
import uuid
from pathlib import Path
from core import engine
from core.config_loader import get_db_params
from core.engine import SentinelEngine
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_postgres import PostgresChatMessageHistory
from datasource.dao.implementation.chat_history_dao_impl import ChatHistoryDaoImpl
from utils.db_conn_management import db_conn_manager

load_dotenv()   # 加载 .env 文件中的环境变量 
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

# --- 1. CSS 样式 (保持你原有的美化逻辑) ---
st.markdown("""
    <style>
    [data-testid="stMetricLabel"] { font-size: 16px !important; }
    [data-testid="stMetricValue"] { font-size: 24px !important; }
    .stApp { background-color: #0e1117; }
    [data-testid="stSidebar"] [data-testid="baseButton-secondary"],
    [data-testid="stSidebar"] [data-testid="baseButton-primary"] {
        display: flex !important;
        justify-content: flex-start !important;
        text-align: left !important;
        width: 100% !important;
        padding-left: 0.5rem !important;
    }
    .block-container { padding-top: 0.09rem !important; padding-bottom: 0rem !important; }
    [data-testid="stHeader"] { display: none !important; }
    button[key="top_logout"] {
        background-color: transparent !important;
        border: 1px solid #444 !important;
        color: #ddd !important;
        border-radius: 4px !important;
        height: 1.5rem !important;
        font-size: 0.8rem !important;
    }
    button[key="top_logout"]:hover { border-color: #ff4b4b !important; color: #ff4b4b !important; }
    
    /* 定位侧边栏中的所有按钮 */
    [data-testid="stSidebar"] button {
        justify-content: flex-start !important;
        text-align: left !important;
        padding-left: 10px !important;
    }
    /* 确保按钮内的文本容器也是左对齐 */
    [data-testid="stSidebar"] button div {
        display: flex;
        justify-content: flex-start;
        width: 100%;
    }
    
    [data-testid="stSidebar"] button div p {
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        max-width: 100%;
    }
    
    /* 隐藏侧边栏头部区域 (包括自带的间距) */
    [data-testid="stSidebarHeader"] {
        display: none !important;
    }
    
    [data-testid="stSidebarUserContent"] {
        padding-top: 1rem !important;
    }
    
    </style>
    """, unsafe_allow_html=True)

# --- 2. 数据库逻辑 ---
def verify_login(username, password):
    try:
        params = get_db_params()
        conn = psycopg2.connect(**params)
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE username = %s AND is_active = TRUE", (username,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        if result:
            return bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8'))
        return False
    except Exception as e:
        st.error(f"Database Error: {e}")
        return False

def get_user_sessions(username):
    """从数据库获取该用户的所有历史会话 ID"""
    try:
        params = get_db_params()
        conn = psycopg2.connect(**params)
        cur = conn.cursor()
        # 这里的逻辑是：找出所有以 username 开头的 session_id 并按时间排序
        query = """
            SELECT DISTINCT session_id 
            FROM chat_history 
            WHERE session_id LIKE %s 
            ORDER BY session_id DESC
        """
        cur.execute(query, (f"{username}_%",))
        sessions = [row[0] for row in cur.fetchall()]
        cur.close()
        conn.close()
        return sessions
    except:
        return []

# --- 3. 引擎加载 ---
@st.cache_resource
def get_sentinel_engine():
    return SentinelEngine()

# --- 4. 登录页面 ---
def show_login_page():
    _, col, _ = st.columns([1, 0.5, 1])
    with col:
        st.write("#")
        with st.form("login_form"):
            l_space, logo_col, r_space = st.columns([1, 2, 1])
            with logo_col:
                if os.path.exists("assets/sentinelflow-logo-login.png"):
                    st.image("assets/sentinelflow-logo-login.png", use_container_width=True)
            user_input = st.text_input("Username")
            pwd_input = st.text_input("Password", type="password")
            if st.form_submit_button("Log In", use_container_width=True, type="primary"):
                if verify_login(user_input, pwd_input):
                    st.session_state.logged_in = True
                    st.session_state.username = user_input
                    st.rerun()
                else:
                    st.error("Invalid credentials")

@st.cache_resource
def get_db_conn():
    db_params = get_db_params()
    # 构造 psycopg3 的连接字符串 (注意: 不需要 postgresql:// 前缀，直接用键值对)
    conn_info = (
        f"dbname={db_params['database']} "
        f"user={db_params['user']} "
        f"password={db_params['password']} "
        f"host={db_params['host']} "
        f"port={db_params['port']}"
    )
    # 必须开启 autocommit，否则 LangChain 的插入操作不会立即生效
    return psycopg.connect(conn_info, autocommit=True)

def generate_chat_title(question: str) -> str:
    """调用 LLM 为当前对话生成一个简短的标题（5-10个字）"""
    try:
        
        system_prompt = (
            "You are a helpful assistant that generates concise titles for user questions. "
            "Given a user's question, produce a very short title (no more than 10 words) that captures the essence of the question. "
            "Return only the title without any explanation or additional text."
        )
        user_prompt = f"Question: {question}"
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("user", user_prompt)
        ])
        title = llm.invoke(prompt).content # 根据你的实际对象调用
        return title.strip().replace('"', '')
    except:
        return question[:10] + "..." # 兜底逻辑

# --- 5. 核心聊天页面 ---
def show_chat_interface():
    engine = get_sentinel_engine()
    username = st.session_state.username

    # 初始化 Session ID (如果不存在)
    if "current_session_id" not in st.session_state:
        # 必须是标准 UUID，满足 langchain-postgres 的校验
        st.session_state.current_session_id = str(uuid.uuid4())
    #
    sync_conn = get_db_conn() 
    history = PostgresChatMessageHistory(
        "chat_history",                      # 位置 1
        st.session_state.current_session_id, # 位置 2
        sync_connection=sync_conn                                                     
    )

    # --- 顶部状态栏 ---
    t_col1, t_col2, t_col3 = st.columns([5, 1, 0.8])
    with t_col2:
        st.markdown(f"<p style='text-align: right; padding-top: 10px;'>👤 <b>{username}</b></p>", unsafe_allow_html=True)
    with t_col3:
        if st.button("Logout", key="top_logout", use_container_width=True):
            st.session_state.logged_in = False
            st.session_state.pop("current_session_id", None)
            st.rerun()
    st.markdown("<hr style='margin: 0px 0px 20px 0px; border-top: 1px solid #333;'>", unsafe_allow_html=True)

    # --- 侧边栏 ---
    with st.sidebar:
        if os.path.exists("assets/sentinelflow-logo-leftside.png"):
            st.image("assets/sentinelflow-logo-leftside.png", width=300)

        # 开启新对话
        if st.button("➕ New Chat", use_container_width=True, type="primary"):
            st.session_state.current_session_id = str(uuid.uuid4())
            st.rerun()
        
        st.markdown("---")
        st.subheader("Chat History")
        
         # 注入样式（仅对侧边栏生效）
        st.markdown(
            """
            <style>
                [data-testid="stSidebar"] button {
                    justify-content: flex-start !important;
                    text-align: left !important;
                    padding-left: 10px !important;}
            </style>
            """, unsafe_allow_html=True
        )
        
        
        # 从数据库动态加载历史列表
        # 使用我们重构后的 get_user_session_list (通过 username 字段查询)
        # 这里的 chat_dao 是你 ChatHistoryDaoImpl 的实例
        
        # 实例化 DAO (传入 SQLAlchemy 的 Session)
        # 建议使用 st.cache_resource 确保 DAO 实例在当前页面会话中复用
        @st.cache_resource
        def get_chat_dao():
            db_session = db_conn_manager.get_session() 
            return ChatHistoryDaoImpl(db_session)
        
        chat_dao = get_chat_dao()
        # 此时 sessions 结构为 [{"id": "...", "title": "..."}, ...]
        sessions = chat_dao.get_user_session_list_with_titles(username) 
        
        if not sessions:
            st.caption("No history yet. Start a new chat!")
        else:
            for session in sessions:
                sid = session["id"]
                st_title = session["title"]
                
                # 1. 确定标题显示
                display_label = st_title if st_title else f"Chat {sid[:8].upper()}"
                
                # 2. 【改进点】判断当前 session 是否为选中状态
                is_active = (sid == st.session_state.current_session_id)
                
                # 3. 根据状态渲染不同样式的按钮
                if st.button(
                    f"{display_label}", 
                    key=f"btn_{sid}", 
                    use_container_width=True,
                    # 如果是当前对话，使用 primary (彩色/加粗)，否则使用 secondary (灰色)
                    type="primary" if is_active else "secondary",
                    # help=f"Full ID: {sid}"
                ):
                    # 只有点击非当前 session 时才需要赋值并刷新
                    if not is_active:
                        st.session_state.current_session_id = sid
                        st.rerun()

    # --- 主聊天区 ---
    st.title("SentinelFlow Financial RAG")
    
    # 5.3 实时显示数据库中的历史消息
    for msg in history.messages:
        role = "user" if msg.type == "human" else "assistant"
        with st.chat_message(role):
            st.markdown(msg.content)

    # 5.4 处理新输入
    if prompt := st.chat_input("Ask about financial data..."):
        # 立即显示用户消息
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # 实时入库：用户消息
        history.add_user_message(prompt)

        # 获取 AI 回答
        with st.chat_message("assistant"):
            with st.spinner("Sentinel Scanning..."):
                try:
                    result = engine.run_query(prompt)
                    answer = result["answer"]
                    
                    if result["status"].startswith("blocked"):
                        st.warning(f"Compliance Alert: {result['status']}")
                    
                    st.markdown(answer)
                    # 实时入库：AI 回答
                    history.add_ai_message(answer)
                    
                    # 同步更新数据库中的 username 归属
                    # 我们一次性把该 session_id 下所有 username 为空的记录都更新掉
                    try:
                        # 获取我们在 st.cache_resource 中定义的 sync_conn
                        sync_conn = get_db_conn()
                        with sync_conn.cursor() as cur:
                            
                            # 检查是否已有标题
                            cur.execute("SELECT title FROM chat_history WHERE session_id = %s AND title IS NOT NULL LIMIT 1", 
                                        (st.session_state.current_session_id,)
                            )
                            
                            row = cur.fetchone()
                            existing_title = row[0] if row else None
                            
                            if not existing_title:
                                # 只有第一轮对话，生成标题
                                summary_title = generate_chat_title(prompt)
                                cur.execute(
                                    """
                                    UPDATE chat_history 
                                    SET username = %s,title = %s 
                                    WHERE session_id = %s AND title IS NULL
                                    """,
                                    (st.session_state.username, summary_title, st.session_state.current_session_id)
                                )
                            else:
                                # 以后只更新归属，不浪费 Token 生成标题
                                cur.execute(
                                    """
                                    UPDATE chat_history 
                                    SET username = %s 
                                    WHERE session_id = %s AND username IS NULL
                                    """,
                                    (st.session_state.username, st.session_state.current_session_id)
                                )
                        # 如果没有开启 autocommit，请取消下面这行的注释
                        # sync_conn.commit(). # 但我们在连接时已经设置了 autocommit=True，所以不需要手动提交
                    except Exception as db_err:
                        st.error(f"Database Patch Error: {db_err}")
                    
                    # 强制刷新以更新 UI 状态
                    st.rerun()
                except Exception as e:
                    st.error(f"Engine Error: {str(e)}")

# --- 6. 入口 ---
def main():
    st.set_page_config(page_title="SentinelFlow Secure Chat", page_icon="🛡️", layout="wide")
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    
    if not st.session_state.logged_in:
        show_login_page()
    else:
        show_chat_interface()

if __name__ == "__main__":
    main()