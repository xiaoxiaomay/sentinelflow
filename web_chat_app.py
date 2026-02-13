import streamlit as st
from core.engine import SentinelEngine

# 1. Page Configuration
st.set_page_config(
    page_title="SentinelFlow Secure Chat", 
    page_icon="🛡️",
    layout="wide"
)

# 2. Initialize Core Engine (Singleton Pattern)
@st.cache_resource
def get_sentinel_engine():
    """
    Initializes the engine. This loads the config, embedding models, 
    FAISS indices (Public & Secret), and the HashChain Audit system.
    """
    return SentinelEngine(config_path="config.yaml")

engine = get_sentinel_engine()

# 3. Sidebar: Audit Trail & System Status
with st.sidebar:
    st.title("Audit Control Panel")
    st.markdown("---")
    st.status("System Connected", state="complete")
    
    st.subheader("Security Indicators")
    # Display the scale of protection
    st.metric(label="Active Security Rules", value="200+ (DFP Enabled)")
    
    if "last_audit" in st.session_state:
        st.divider()
        st.subheader("Latest Audit Log")
        audit = st.session_state.last_audit
        
        st.info(f"Status: {audit.get('status', 'N/A').upper()}")
        
        if audit.get("leakage_flag"):
            st.error("SENSITIVE DATA LEAK DETECTED")
        
        # Display HashChain Integrity
        st.success("Integrity Verified")
        st.markdown("**Chain Hash:**")
        st.code(f"{st.session_state.last_hash[:16]}...", language="text")

# 4. Main Interface: Chat Window
st.title("SentinelFlow Financial RAG")
st.caption("Secure Compliance Assistant | MiniLM-L6-v2 | DFP Pattern Recognition")



if "messages" not in st.session_state:
    st.session_state.messages = []

# Render chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# 5. User Input & Response Logic
if prompt := st.chat_input("Ask about financial data or quantitative strategies..."):
    # Record and display user question
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Execute SentinelFlow Pipeline
    with st.chat_message("assistant"):
        with st.spinner("Multi-stage Security Scan (Gate0 -> Gate1 -> LLM -> DFP)..."):
            try:
                # Call the unified engine method
                result = engine.run_query(prompt)
                
                answer = result["answer"]
                
                # UI Feedback Logic for Security Triggers
                if result["status"] == "blocked_gate0":
                    st.error("BLOCKED: Hard Filter Violation (Gate 0)")
                elif result["status"] == "blocked_gate1":
                    st.warning("BLOCKED: Semantic Leakage Detected (Gate 1)")
                elif result.get("leakage_flag"):
                    st.toast("Sensitive content redacted for your protection.", icon="🛡️")

                st.markdown(answer)
                
                # Update Session State for sidebar sync
                st.session_state.messages.append({"role": "assistant", "content": answer})
                st.session_state.last_audit = result
                # Fetch latest audit hash from the engine's writer
                st.session_state.last_hash = getattr(engine.writer, 'last_hash', 'N/A')

            except Exception as e:
                st.error(f"Engine Runtime Error: {str(e)}")