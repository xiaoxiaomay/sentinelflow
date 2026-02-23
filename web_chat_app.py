import streamlit as st
import json
import psycopg2
import yaml
import os
import bcrypt
from core.config_loader import get_db_params
from pathlib import Path
from core.engine import SentinelEngine

# --- 1. 配置与样式 ---
st.markdown("""
    <style>
    [data-testid="stMetricLabel"] { font-size: 16px !important; }
    [data-testid="stMetricValue"] { font-size: 24px !important; }
    .stApp { background-color: #0e1117; }
    
    /* 1. 强制侧边栏按钮内部对齐 */
    [data-testid="stSidebar"] [data-testid="baseButton-secondary"],
    [data-testid="stSidebar"] [data-testid="baseButton-primary"] {
        display: flex !important;
        justify-content: flex-start !important; /* 核心：对齐容器 */
        text-align: left !important;            /* 核心：文字对齐 */
        width: 100% !important;
        padding-left: 0.5rem !important;
    }

    /* 2. 针对按钮内的文字标签（Streamlit 内部通常用 p 标签包裹文字） */
    [data-testid="stSidebar"] [data-testid="baseButton-secondary"] p,
    [data-testid="stSidebar"] [data-testid="baseButton-primary"] p {
        margin-left: 0 !important;
        text-align: left !important;
        flex: none !important; /* 防止文字在 Flex 容器中居中撑开 */
    }
    
    /* 3. 悬停效果美化 */
    [data-testid="stSidebar"] button:hover {
        border-color: #4CAF50 !important;
        background-color: rgba(255, 255, 255, 0.05) !important;
    }
    
    /* 强力定位右上角按钮 */
    div[data-testid="stColumn"]:has(button[key="top_logout"]) {
        display: flex;
        align-items: center;
        justify-content: flex-end;
    }
    
    /* 之前你写的靠左 CSS 继续保留 */
    [data-testid="stSidebar"] [data-testid="baseButton-secondary"] {
        justify-content: flex-start !important;
        text-align: left !important;
    }
    
    /* 针对右上角 Logout 按钮的特殊样式 */
    button[key="top_logout"] {
        background-color: transparent !important;
        border: 1px solid #444 !important;
        color: #ddd !important;
        border-radius: 4px !important;
        height: 32px !important;
    }
    
    button[key="top_logout"]:hover {
        border-color: #ff4b4b !important; /* 悬停时显示红色提醒 */
        color: #ff4b4b !important;
    }
    
    /* 强制调整主容器的上下边距 */
    .block-container {
        padding-top: 0.09rem !important;
        padding-bottom: 0rem !important;
    }
    
    /* 配合隐藏 Header，让内容完全贴顶 */
    [data-testid="stHeader"] {
        display: none !important;
    }

    /* 让右上角的文字和按钮对齐更美观 */
    [data-testid="stVerticalBlock"] > div:has(button[kind="secondary"]) {
        gap: 0px !important;
    }
    
    /* 调整登出按钮的高度，使其更小巧 */
    button[key="top_logout"] {
        height: 1.5rem !important;
        line-height: 1.5rem !important;
        font-size: 0.8rem !important;
    }
    
    /* 强制表单内的图片容器水平居中 */
    [data-testid="stForm"] [data-testid="stImage"] {
       
        width: 200px !important;    /* 固定宽度 */
        height: auto !important;    /* 高度自适应 */
        margin: 0 auto !important;
        display: block;
        
        /* 关键：防止模糊 */
        image-rendering: -webkit-optimize-contrast; /* 提高对比度/清晰度 */
        image-rendering: crisp-edges;               /* 保持边缘锐利 */
        
        /* 如果背景是黑色的，可以加一点点对比度增强 */
        filter: contrast(1.1) brightness(1.1);
        display: flex !important;
        justify-content: center !important;
        align-items: center !important;
    }

    /* 移除 Logo 图片可能的默认边距 */
    [data-testid="stForm"] [data-testid="stImage"] img {
        margin: 0 auto !important;
    }
    
    /* 1. 彻底隐藏侧边栏顶部的默认 Header 容器 */
    [data-testid="stSidebarHeader"] {
        display: none !important;
    }

    /* 2. 移除隐藏后的多余边距，让你的 Logo 真正贴顶 */
    [data-testid="stSidebar"] [data-testid="stVerticalBlock"] {
        padding-top: 0rem !important;
    }
    
    /* 3. 可选：如果你觉得 Logo 离最顶端太近，可以微调你自己的容器 */
    .sidebar-logo-container {
        margin-top: -30px !important; /* 根据实际视觉效果上下微调 */
    }
    
    </style>
    """, unsafe_allow_html=True)


# --- 数据库验证逻辑 ---
def load_db_config():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, 'config.yaml')
    with open(config_path, 'r', encoding="utf-8") as f:
        return yaml.safe_load(f)['db']


def verify_login(username, password):
    try:
        params = get_db_params()  # 使用 ** 语法直接将字典解包为函数参数
        conn = psycopg2.connect(**params)
        cur = conn.cursor()
        # 注意：这里查询的是你之前存入的哈希字段 password_hash
        cur.execute("SELECT password_hash FROM users WHERE username = %s AND is_active = TRUE", (username,))
        result = cur.fetchone()
        cur.close()
        conn.close()

        if result:
            return bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8'))
        return False
    except Exception as e:
        st.error(f"Database Connection Error: {e}")
        return False


# --- 3. 初始化 RAG 引擎 (单例) ---
@st.cache_resource
def get_sentinel_engine():
    return SentinelEngine()


# --- 4. 辅助函数：读取审计日志 ---
def get_recent_audit_steps(limit=5):
    audit_file = "data/audit/audit_log.jsonl"
    if not Path(audit_file).exists(): return []
    try:
        with open(audit_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            return [json.loads(line) for line in lines[-limit:]]
    except:
        return []


# --- 5. 登录界面 UI ---
def show_login_page():
    _, col, _ = st.columns([1, 0.5, 1])
    with col:
        st.write("#")
        # 使用 st.form 包裹登录逻辑
        with st.form("login_form", clear_on_submit=False):
            # --- 关键修改：在 Form 内部再次划分列来强制居中 Logo ---
            l_space, logo_col, r_space = st.columns([1, 2, 1])
            with logo_col:
                logo_path = "assets/sentinelflow-logo-login.png"
                if os.path.exists(logo_path):
                    st.image(logo_path, use_container_width=True)

            # 标题也要居中
            # st.markdown("<h2 style='text-align: center; color: white; margin-top: -10px;'>SentinelFlow</h2>", unsafe_allow_html=True)

            user_input = st.text_input("Username")
            pwd_input = st.text_input("Password", type="password")

            # 使用 form_submit_button 替代普通的 st.button
            # 这样用户在任一输入框按回车，都会触发此按钮逻辑
            submit_button = st.form_submit_button("Log In", use_container_width=True, type="primary")

            if submit_button:
                if verify_login(user_input, pwd_input):
                    st.session_state.logged_in = True
                    st.session_state.username = user_input
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error("Invalid credentials")


# --- 6. 核心聊天界面 UI (整合你之前的逻辑) ---
def show_chat_interface():
    engine = get_sentinel_engine()

    # 初始化存档容器（如果不存在）
    if "chat_archive" not in st.session_state:
        st.session_state.chat_archive = []

    # --- 新增：顶部导航栏 (右上角用户信息与登出) ---
    # 使用 3 列布局，第一列占满剩余空间，后两列放用户信息和登出按钮
    t_col1, t_col2, t_col3 = st.columns([5, 1, 0.8])

    with t_col2:
        # 垂直居中显示用户名
        st.markdown(f"<p style='text-align: right; padding-top: 10px;'>👤 <b>{st.session_state.username}</b></p>",
                        unsafe_allow_html=True)

    with t_col3:
        # 登出按钮，使用之前定义的 top_logout 样式
        if st.button("Logout", key="top_logout", use_container_width=True):
            st.session_state.logged_in = False
            st.rerun()
    st.markdown("<hr style='margin: 0px 0px 20px 0px; border-top: 1px solid #333;'>", unsafe_allow_html=True)
    # --- Sidebar (chat history and audit panel) ---
    with st.sidebar:
        logo_path = "assets/sentinelflow-logo-leftside.png"
        if os.path.exists(logo_path):
            # 给 Logo 一个唯一的容器名方便 CSS 控制
            st.markdown('<div class="sidebar-logo-container">', unsafe_allow_html=True)
            st.image(logo_path, width=320)  # 侧边栏建议设为 320 显得更精致
            st.markdown('</div>', unsafe_allow_html=True)

        # New Chat 按钮放在侧边栏顶部，显眼位置
        if st.button("➕ New Chat", use_container_width=True, type="primary"):
            if st.session_state.messages:
                first_question = st.session_state.messages[0]["content"][:15] + "..."
                st.session_state.chat_archive.append({
                    "title": first_question,
                    "msgs": st.session_state.messages.copy()
                })
                st.session_state.messages = []
                st.rerun()
        st.markdown("---")

        # 渲染对话历史列表 (已通过 CSS 靠左)
        st.subheader("Chat History")
        if not st.session_state.chat_archive:
            st.caption("No history yet.")
        else:
            for idx, chat in enumerate(reversed(st.session_state.chat_archive)):
                if st.button(f"💬 {chat['title']}", key=f"hist_{idx}", use_container_width=True):
                    st.session_state.messages = chat['msgs'].copy()
                    st.rerun()

        st.markdown("---")

        st.subheader("Audit Control")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("DB Status", "Connected" if engine.db_conn else "Offline")
        with col2:
            st.metric("Security", "DFP Active")

        st.subheader("🔗 HashChain Tracker")
        logs = get_recent_audit_steps()
        if not logs:
            st.info("Awaiting command...")
        else:
            for log in reversed(logs):
                event = log.get("event_type", "unknown")
                icon = "🔍" if "check" in event else "📝"
                if event == "final_output": icon = "✅"
                with st.expander(f"{icon} {event.upper()}"):
                    st.caption(f"Time: {log.get('timestamp', 'N/A')}")
                    st.code(f"Hash: {log.get('hash', 'N/A')[:12]}...", language="text")

    # Main Chat Area
    st.title("SentinelFlow Financial RAG")
    st.caption("PostgreSQL Vector DB | Multi-layer Compliance System")

    if "messages" not in st.session_state:
        st.session_state.messages = []

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    if prompt := st.chat_input("Ask about financial data..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            with st.spinner("Sentinel Multi-stage Scan..."):
                try:
                    result = engine.run_query(prompt)
                    if result["status"] == "blocked_gate0":
                        st.error("Gate 0: Policy Violation")
                    elif result["status"] == "blocked_gate1":
                        st.warning("Gate 1: Data Leak Blocked")

                    st.markdown(result["answer"])
                    st.session_state.messages.append({"role": "assistant", "content": result["answer"]})
                    st.rerun()
                except Exception as e:
                    st.error(f"Engine Exception: {str(e)}")


# --- 7. 主程序入口 ---
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