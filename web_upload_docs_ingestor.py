import os
import time
import tempfile
import streamlit as st
from datasource.knowledge_base import KnowledgeBaseService
from datasource.dao.implementation.financial_corpus_dao_impl import FinancialCorpusDaoImpl
from datasource.dao.implementation.ingestion_tasks_dao_impl import IngestionTaskDaoImpl
from utils.db_conn_management import db_conn_manager
from sentence_transformers import SentenceTransformer
from langchain_text_splitters import RecursiveCharacterTextSplitter
from core.config_loader import get_engine_configs

# --- 1. 初始化后台服务 (单例模式) ---
@st.cache_resource
def init_kb_service():
    """
    初始化核心 Service，模型和数据库连接仅在此加载一次
    """
    session = db_conn_manager.get_session()
    configs = get_engine_configs()
    embed_cfg = configs.get("embedding", {})
    
    # 初始化 DAO 层
    fc_dao = FinancialCorpusDaoImpl(session)
    it_dao = IngestionTaskDaoImpl(session)
    
    # 加载 Embedding 模型
    model = SentenceTransformer(embed_cfg.get('model_name'))
    
    # 配置文本切分器
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=embed_cfg.get("chunk_size", 800),
        chunk_overlap=embed_cfg.get("chunk_overlap", 100),
        length_function=len,
        separators=embed_cfg.get("separators")
    )
    
    return KnowledgeBaseService(fc_dao, it_dao, model, text_splitter)

# 启动知识库服务
service = init_kb_service()


# 创建两列，第一列放 Logo，第二列放 Title
# [1, 4] 表示第二列的宽度是第一列的 4 倍
col1, col2 = st.columns([1, 4])
# --- 2. Streamlit 页面配置 ---
st.set_page_config(page_title="SentinelFlow Ingestion", layout="wide")
with col1:
    if os.path.exists("assets/sentinelflow-logo-leftside.png"):
        # 这里的 width 可以设小一点，或者使用 use_container_width=True
        st.image("assets/sentinelflow-logo-leftside.png", width=300) 

with col2:
    # 调整标题的对齐，使其在视觉上与 logo 居中对齐（可选）
    st.title("Multi-File Knowledge Ingestion")
st.markdown("---")

# 多文件上传组件
uploaded_files = st.file_uploader(
    "Select Financial Documents (PDF, CSV, or JSONL):",
    type=['pdf', 'csv', 'jsonl'],
    accept_multiple_files=True,
)

if uploaded_files:
    st.info(f"Selected **{len(uploaded_files)}** files. Ready to process.")
    
    if st.button("Start Ingestion", use_container_width=True):
        # 进度反馈组件
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        success_count = 0
        total_chunks = 0
        
        # 遍历文件列表
        for index, uploader_file in enumerate(uploaded_files):
            file_name = uploader_file.name
            file_ext = os.path.splitext(file_name)[1].lower()
            
            status_text.text(f"Processing ({index+1}/{len(uploaded_files)}): {file_name}...")
            
            # --- 使用 tempfile 处理临时文件 ---
            # delete=False 是关键，因为我们需要先关闭文件，再让 Service 根据路径读取它
            with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp_file:
                tmp_file.write(uploader_file.getbuffer())
                tmp_path = tmp_file.name # 获取系统分配的临时路径

            try:
                # 调用核心 Service 处理入库逻辑
                # 即使是临时路径，handle_file 内部仍会记录原始文件名
                chunks = service.handle_file(tmp_path, source_from='web_upload')
                
                total_chunks += chunks
                success_count += 1
                
            except Exception as e:
                st.error(f"Failed to process {file_name}: {str(e)}")
            
            finally:
                # 无论入库成功还是抛出异常，必须清理临时文件
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            
            # 更新总体进度
            progress_bar.progress((index + 1) / len(uploaded_files))

        # --- 处理结果汇总 ---
        status_text.text("All tasks finished!")
        st.success(f"Successfully processed **{success_count}** files, created **{total_chunks}** new database chunks.")
        
        if success_count == len(uploaded_files):
            st.balloons()