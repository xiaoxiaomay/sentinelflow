# app.py
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st

st.set_page_config(page_title="SentinelFlow Dashboard", layout="wide")

APP_TITLE = "SentinelFlow — RAG + Leakage Firewall + Evidence Chain"


# ----------------------------
# Utils
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
                # skip bad line
                continue
    return rows


def get_body(ev: Dict[str, Any]) -> Dict[str, Any]:
    return ev.get("body", {}) if isinstance(ev.get("body", {}), dict) else {}


def safe_get(d: Dict[str, Any], keys: List[str], default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def short(s: Optional[str], n=10) -> str:
    if not s:
        return ""
    return s[:n]


def canonical_json(obj: Any) -> str:
    # deterministic serialization (must match audit.py if you used same separators/sort_keys)
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_str(s: str) -> str:
    import hashlib

    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ----------------------------
# Chain validators
# ----------------------------
def verify_event_hash(ev: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Verify event_hash matches sha256(canonical_json({ts,type,body,prev_hash}))
    This matches the common pattern used in HashChainWriter.
    """
    ts = ev.get("ts")
    typ = ev.get("type")
    body = get_body(ev)
    prev_hash = ev.get("prev_hash", "0" * 64)
    expected = sha256_str(canonical_json({"ts": ts, "type": typ, "body": body, "prev_hash": prev_hash}))
    got = ev.get("event_hash", "")
    if expected == got:
        return True, ""
    return False, f"event_hash mismatch (expected {expected[:10]}.. got {got[:10]}..)"


def verify_session_chain(events: List[Dict[str, Any]]) -> Tuple[bool, pd.DataFrame, str]:
    """
    Validate chain continuity ONLY within selected session.
    We DO NOT require global adjacency in the file.
    We check:
      - each event's prev_hash equals previous event's event_hash (in session order)
      - optionally verify event_hash integrity for each event
    """
    if not events:
        return True, pd.DataFrame(), "No events"

    rows = []
    ok_all = True
    msg = ""

    prev = None
    for i, ev in enumerate(events):
        link_ok = True
        if prev is not None:
            link_ok = (ev.get("prev_hash") == prev.get("event_hash"))
        hash_ok, hash_msg = verify_event_hash(ev)

        if not link_ok or not hash_ok:
            ok_all = False
            if not msg:
                msg = "link or hash mismatch"

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

    return ok_all, pd.DataFrame(rows), msg


def verify_global_chain(events_in_file_order: List[Dict[str, Any]]) -> Tuple[bool, pd.DataFrame, str]:
    """
    Validate chain continuity across the WHOLE log, in file order.
    For multi-session logs, this can show breaks if your writer uses per-session chaining.
    If your writer uses a single global chain, this should be OK.
    """
    if not events_in_file_order:
        return True, pd.DataFrame(), "No events"

    rows = []
    ok_all = True
    msg = ""

    prev = None
    for i, ev in enumerate(events_in_file_order):
        link_ok = True
        if prev is not None:
            link_ok = (ev.get("prev_hash") == prev.get("event_hash"))
        hash_ok, hash_msg = verify_event_hash(ev)

        if not link_ok or not hash_ok:
            ok_all = False
            if not msg:
                msg = "link or hash mismatch"

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

    return ok_all, pd.DataFrame(rows), msg


# ----------------------------
# Parse & normalize
# ----------------------------
def extract_session_id(ev: Dict[str, Any]) -> Optional[str]:
    body = get_body(ev)
    return body.get("session_id") or body.get("sid")


def summarize_event_row(ev: Dict[str, Any]) -> Dict[str, Any]:
    body = get_body(ev)
    typ = ev.get("type")

    row = {
        "ts": ev.get("ts"),
        "type": typ,
        "session_id": extract_session_id(ev),
        "query": body.get("query"),
        "model": body.get("model"),
        "latency_s": body.get("latency_s"),
        "raw_answer_chars": body.get("raw_answer_chars"),
        "final_answer_chars": body.get("final_answer_chars"),
        "leakage_flag": safe_get(body, ["summary", "leakage_flag"]),
        "trigger_reason": safe_get(body, ["summary", "trigger_reason"]),
        "hard_hits": safe_get(body, ["summary", "hard_hits"]),
        "soft_hits": safe_get(body, ["summary", "soft_hits"]),
        "cascade_triggered": safe_get(body, ["summary", "cascade_triggered"]),
    }

    # allow "final_output" schema variants
    if typ == "final_output":
        row["final_answer_chars"] = body.get("final_answer_chars") or body.get("final_chars") or row["final_answer_chars"]
        row["leakage_flag"] = body.get("leakage_flag") if row["leakage_flag"] is None else row["leakage_flag"]
        row["trigger_reason"] = body.get("trigger_reason") if row["trigger_reason"] is None else row["trigger_reason"]

    # query_precheck schema variants
    if typ == "query_precheck":
        row["trigger_reason"] = body.get("trigger_reason") or row["trigger_reason"]
        row["leakage_flag"] = body.get("blocked") if row["leakage_flag"] is None else row["leakage_flag"]

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
        if ev.get("type") == "llm_response":
            out["llm_response"] = get_body(ev)
        if ev.get("type") == "final_output":
            out["final_output"] = get_body(ev)
    return out


def extract_leakage_details(events: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Try to find:
      - summary: body.summary or body (if already summary-shaped)
      - sentences: body.sentences / body.details.sentences / body.leak_result.sentences
    """
    for ev in events:
        if ev.get("type") == "leakage_scan":
            body = get_body(ev)
            summary = body.get("summary") or body.get("result") or body
            sentences = (
                body.get("sentences")
                or safe_get(body, ["details", "sentences"], default=None)
                or safe_get(body, ["leak_result", "sentences"], default=None)
                or []
            )
            if not isinstance(sentences, list):
                sentences = []
            return summary if isinstance(summary, dict) else {}, sentences
    return {}, []


# ----------------------------
# UI
# ----------------------------
st.title(APP_TITLE)

with st.sidebar:
    st.header("Audit log")
    default_path = "data/audit/audit_log.jsonl"
    audit_path = st.text_input("audit_log.jsonl path", value=default_path)

events = read_jsonl(audit_path)

# basic metrics
total_events = len(events)
session_ids = [extract_session_id(e) for e in events]
session_ids = [s for s in session_ids if s]
unique_sessions = sorted(set(session_ids))

# leakage events: count leakage_scan events only
leakage_events = sum(1 for e in events if e.get("type") in ("leakage_scan", "query_precheck"))

m1, m2, m3 = st.columns(3)
m1.metric("Total events", total_events)
m2.metric("Unique sessions", len(unique_sessions))
m3.metric("Leakage events", leakage_events)

st.subheader("Sessions")
selected_session = st.selectbox("Select session_id", options=unique_sessions, index=0 if unique_sessions else None)

session_events = [e for e in events if extract_session_id(e) == selected_session] if selected_session else []
# sort session events by ts string (ISO) if present
session_events_sorted = sorted(session_events, key=lambda x: x.get("ts") or "")

# Validation mode toggle
st.subheader("Evidence Chain validation")
left, right = st.columns([2, 3])

with left:
    mode = st.radio("validation mode", options=["session", "global"], horizontal=True, index=0)

with right:
    if mode == "session":
        ok, df_chain, msg = verify_session_chain(session_events_sorted)
        st.success("Chain OK ✅ (session chain)") if ok else st.error("Chain BROKEN ❌ (session chain)")
        if not ok and msg:
            st.caption(msg)
    else:
        ok, df_chain, msg = verify_global_chain(events)
        st.success("Chain OK ✅ (global chain)") if ok else st.error("Chain BROKEN ❌ (global chain)")
        if not ok and msg:
            st.caption(msg)

st.dataframe(df_chain, use_container_width=True, hide_index=True)

# Timeline table
st.subheader("Timeline (events)")
df_tl = pd.DataFrame([summarize_event_row(e) for e in session_events_sorted])
st.dataframe(df_tl, use_container_width=True, hide_index=True)

# Key artifacts
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
    st.code(json.dumps(summary.get("prompt_built", {}), ensure_ascii=False, indent=2))
    st.code(json.dumps(summary.get("llm_response", {}), ensure_ascii=False, indent=2))
    st.code(json.dumps(summary.get("final_output", {}), ensure_ascii=False, indent=2))

# Leakage details
st.subheader("Leakage scan details (for demo visibility)")
leak_summary, leak_sentences = extract_leakage_details(session_events_sorted)

st.markdown("**Summary**")
st.code(json.dumps(leak_summary, ensure_ascii=False, indent=2))

st.markdown("**Sentence-level decisions**")
if leak_sentences:
    st.dataframe(pd.DataFrame(leak_sentences), use_container_width=True, hide_index=True)
else:
    st.info("No sentence-level details found. (If you write sentences into audit, the table will show here.)")

# Debug expander
with st.expander("Raw events (selected session)"):
    st.write(session_events_sorted)