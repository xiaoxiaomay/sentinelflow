# scripts/dashboard.py
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st

st.set_page_config(page_title="SentinelFlow Dashboard", layout="wide")
APP_TITLE = "SentinelFlow — RAG + Leakage Firewall + Evidence Chain"


# ----------------------------
# Basic helpers
# ----------------------------
def read_jsonl(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    rows = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def get_body(ev: Dict[str, Any]) -> Dict[str, Any]:
    b = ev.get("body", {})
    return b if isinstance(b, dict) else {}


def extract_session_id(ev: Dict[str, Any]) -> Optional[str]:
    b = get_body(ev)
    return b.get("session_id") or b.get("sid")


def short(s: Optional[str], n=10) -> str:
    if not s:
        return ""
    return str(s)[:n]


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_str(s: str) -> str:
    import hashlib

    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ----------------------------
# Hash validation
# ----------------------------
def verify_event_hash(ev: Dict[str, Any]) -> bool:
    """
    Verify event_hash matches sha256(canonical_json({ts,type,body,prev_hash}))
    Must match your audit.py implementation.
    """
    ts = ev.get("ts")
    typ = ev.get("type")
    body = get_body(ev)
    prev_hash = ev.get("prev_hash", "0" * 64)
    expected = sha256_str(canonical_json({"ts": ts, "type": typ, "body": body, "prev_hash": prev_hash}))
    got = ev.get("event_hash", "")
    return expected == got


def verify_chain(events: List[Dict[str, Any]]) -> Tuple[bool, pd.DataFrame]:
    """
    Generic chain validator: checks link_ok (prev_hash matches previous event_hash)
    and hash_ok (event_hash integrity) for the given ordered list.
    """
    if not events:
        return True, pd.DataFrame()

    rows = []
    ok_all = True
    prev = None
    for i, ev in enumerate(events):
        link_ok = True
        if prev is not None:
            link_ok = (ev.get("prev_hash") == prev.get("event_hash"))
        hash_ok = verify_event_hash(ev)
        if not (link_ok and hash_ok):
            ok_all = False

        rows.append(
            {
                "i": i,
                "ts": ev.get("ts"),
                "type": ev.get("type"),
                "link_ok": link_ok,
                "hash_ok": hash_ok,
                "prev_hash_prefix": short(ev.get("prev_hash"), 10),
                "event_hash_prefix": short(ev.get("event_hash"), 10),
            }
        )
        prev = ev

    return ok_all, pd.DataFrame(rows)


# ----------------------------
# Event summarization for tables
# ----------------------------
def summarize_event_row(ev: Dict[str, Any]) -> Dict[str, Any]:
    body = get_body(ev)
    typ = ev.get("type")

    # common fields
    row = {
        "ts": ev.get("ts"),
        "type": typ,
        "session_id": extract_session_id(ev),
        "query": body.get("query"),
        "model": body.get("model"),
        "latency_s": body.get("latency_s"),
        "raw_answer_chars": body.get("raw_answer_chars"),
        "final_answer_chars": body.get("final_answer_chars"),
        "leakage_flag": (body.get("summary", {}) or {}).get("leakage_flag"),
        "trigger_reason": (body.get("summary", {}) or {}).get("trigger_reason"),
        "hard_hits": (body.get("summary", {}) or {}).get("hard_hits"),
        "soft_hits": (body.get("summary", {}) or {}).get("soft_hits"),
        "cascade_triggered": (body.get("summary", {}) or {}).get("cascade_triggered"),
    }

    # final_output variants
    if typ == "final_output":
        row["final_answer_chars"] = body.get("final_answer_chars") or body.get("final_chars") or row["final_answer_chars"]
        if row["leakage_flag"] is None and "leakage_flag" in body:
            row["leakage_flag"] = body.get("leakage_flag")
        if row["trigger_reason"] is None and "trigger_reason" in body:
            row["trigger_reason"] = body.get("trigger_reason")

    # query_precheck variants
    if typ == "query_precheck":
        row["trigger_reason"] = body.get("trigger_reason") or row["trigger_reason"]
        if row["leakage_flag"] is None and "blocked" in body:
            row["leakage_flag"] = body.get("blocked")

    return row


def extract_retrieved_docs(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for ev in events:
        if ev.get("type") == "retrieve":
            docs = get_body(ev).get("docs", [])
            if isinstance(docs, list):
                return docs
    return []


def extract_prompt_summary(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    out = {}
    for ev in events:
        if ev.get("type") == "prompt_built":
            out["prompt_built"] = get_body(ev)
        elif ev.get("type") == "llm_response":
            out["llm_response"] = get_body(ev)
        elif ev.get("type") == "final_output":
            out["final_output"] = get_body(ev)
        elif ev.get("type") == "query_precheck":
            out["query_precheck"] = get_body(ev)
    return out


def extract_leakage_details(events: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    for ev in events:
        if ev.get("type") == "leakage_scan":
            body = get_body(ev)
            summary = body.get("summary") or body
            # try multiple possible placements
            sentences = body.get("sentences") or (body.get("details", {}) or {}).get("sentences") or []
            if not isinstance(sentences, list):
                sentences = []
            if not isinstance(summary, dict):
                summary = {}
            return summary, sentences
    return {}, []


# ----------------------------
# UI
# ----------------------------
st.title(APP_TITLE)

with st.sidebar:
    st.header("Audit log")
    audit_path = st.text_input("audit_log.jsonl path", value="data/audit/audit_log.jsonl")

events = read_jsonl(audit_path)

total_events = len(events)
session_ids = [extract_session_id(e) for e in events]
unique_sessions = sorted({s for s in session_ids if s})

leakage_events = sum(1 for e in events if e.get("type") in ("leakage_scan", "query_precheck"))

m1, m2, m3 = st.columns(3)
m1.metric("Total events", total_events)
m2.metric("Unique sessions", len(unique_sessions))
m3.metric("Leakage events", leakage_events)

st.subheader("Sessions")
selected_session = st.selectbox("Select session_id", options=unique_sessions, index=0 if unique_sessions else None)

session_events = [e for e in events if extract_session_id(e) == selected_session] if selected_session else []
session_events_sorted = sorted(session_events, key=lambda x: x.get("ts") or "")

st.subheader("Evidence Chain validation")
mode = st.radio("validation mode", options=["session", "global"], horizontal=True, index=0)

if mode == "session":
    ok, df_chain = verify_chain(session_events_sorted)
    if ok:
        st.success("Chain OK ✅ (session chain)")
    else:
        st.error("Chain BROKEN ❌ (session chain)")
else:
    ok, df_chain = verify_chain(events)  # file order global
    if ok:
        st.success("Chain OK ✅ (global chain)")
    else:
        st.error("Chain BROKEN ❌ (global chain)")

st.dataframe(df_chain, use_container_width=True, hide_index=True)

st.subheader("Timeline (events)")
df_tl = pd.DataFrame([summarize_event_row(e) for e in session_events_sorted])
st.dataframe(df_tl, use_container_width=True, hide_index=True)

st.subheader("Key artifacts")
c1, c2 = st.columns([3, 2])

with c1:
    st.markdown("**Top-k Retrieved Docs**")
    docs = extract_retrieved_docs(session_events_sorted)
    if docs:
        st.dataframe(pd.DataFrame(docs), use_container_width=True, hide_index=True)
    else:
        st.info("No retrieve docs found in this session.")

with c2:
    st.markdown("**Prompt / Model / Output summary**")
    summary = extract_prompt_summary(session_events_sorted)
    st.code(json.dumps(summary, ensure_ascii=False, indent=2))

st.subheader("Leakage scan details (for demo visibility)")
leak_summary, leak_sentences = extract_leakage_details(session_events_sorted)
st.markdown("**Summary**")
st.code(json.dumps(leak_summary, ensure_ascii=False, indent=2))

st.markdown("**Sentence-level decisions**")
if leak_sentences:
    st.dataframe(pd.DataFrame(leak_sentences), use_container_width=True, hide_index=True)
else:
    st.info("No sentence-level details found (not written to audit yet).")

with st.expander("Raw events (selected session)"):
    st.write(session_events_sorted)