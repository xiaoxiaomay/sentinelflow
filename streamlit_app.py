import json
import os
import hashlib
import pandas as pd
import streamlit as st

st.set_page_config(page_title="SentinelFlow Dashboard", layout="wide")

def canonical_json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def load_jsonl(path: str):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows

def validate_chain(events):
    """
    Minimal validation:
    - prev_hash of current equals event_hash of previous
    - recompute event_hash from (prev_hash + canonical_json(type/body/ts))
      NOTE: must match how your core/audit.py computes it.
    If your audit.py uses a different formula, adjust here accordingly.
    """
    results = []
    ok = True

    prev_event_hash = None
    for i, e in enumerate(events):
        prev_hash = e.get("prev_hash")
        event_hash = e.get("event_hash")

        # linkage check
        if i == 0:
            link_ok = True  # genesis
        else:
            link_ok = (prev_hash == prev_event_hash)

        # recompute check (best-effort)
        payload = {"ts": e.get("ts"), "type": e.get("type"), "body": e.get("body")}
        recomputed = sha256_str((prev_hash or "") + canonical_json(payload))
        hash_ok = (event_hash == recomputed)

        row_ok = link_ok and hash_ok
        ok = ok and row_ok

        results.append({
            "i": i,
            "type": e.get("type"),
            "link_ok": link_ok,
            "hash_ok": hash_ok,
            "prev_hash_prefix": (prev_hash or "")[:10],
            "event_hash_prefix": (event_hash or "")[:10],
        })
        prev_event_hash = event_hash

    return ok, pd.DataFrame(results)

def flatten_events(events):
    out = []
    for e in events:
        body = e.get("body") or {}
        out.append({
            "ts": e.get("ts"),
            "type": e.get("type"),
            "session_id": body.get("session_id"),
            "model": body.get("model"),
            "query": body.get("query"),
            "leakage_flag": (body.get("summary") or {}).get("leakage_flag") if e.get("type") == "leakage_scan" else None,
            "trigger_reason": (body.get("summary") or {}).get("trigger_reason") if e.get("type") == "leakage_scan" else None,
            "event_hash": e.get("event_hash"),
            "prev_hash": e.get("prev_hash"),
        })
    return pd.DataFrame(out)

st.title("SentinelFlow — RAG + Leakage Firewall + Evidence Chain")

default_path = "data/audit/audit_log.jsonl"
path = st.text_input("Audit log path", value=default_path)

if not os.path.exists(path):
    st.error(f"File not found: {path}")
    st.stop()

events = load_jsonl(path)
df = flatten_events(events)

col1, col2, col3 = st.columns(3)
col1.metric("Total events", len(events))
col2.metric("Unique sessions", df["session_id"].nunique(dropna=True))
col3.metric("Leakage events", int((df["type"] == "leakage_scan").sum()))

st.subheader("Sessions")
sessions = [s for s in df["session_id"].dropna().unique().tolist()]
sessions.sort()

selected = st.selectbox("Select session_id", sessions) if sessions else None
if not selected:
    st.info("No session_id found in log yet.")
    st.stop()

sess_events = [e for e in events if (e.get("body") or {}).get("session_id") == selected]
sess_df = flatten_events(sess_events)

left, right = st.columns([1, 1])

with left:
    st.markdown("### Timeline (events)")
    st.dataframe(sess_df[["ts", "type", "query", "model", "leakage_flag", "trigger_reason"]], use_container_width=True)

with right:
    st.markdown("### Evidence Chain validation")
    ok, chain_df = validate_chain(sess_events)
    st.success("Chain OK ✅" if ok else "Chain BROKEN ❌")
    st.dataframe(chain_df, use_container_width=True)

st.markdown("### Key artifacts")
# show retrieve docs
retrieve = next((e for e in sess_events if e.get("type") == "retrieve"), None)
if retrieve:
    docs = (retrieve.get("body") or {}).get("docs", [])
    st.markdown("**Top-k Retrieved Docs**")
    st.dataframe(pd.DataFrame(docs), use_container_width=True)

llm_resp = next((e for e in sess_events if e.get("type") == "llm_response"), None)
if llm_resp:
    raw_chars = (llm_resp.get("body") or {}).get("raw_answer_chars")
    st.markdown(f"**LLM response** (raw chars: {raw_chars})")

leak = next((e for e in sess_events if e.get("type") == "leakage_scan"), None)
if leak:
    summary = (leak.get("body") or {}).get("summary", {})
    st.markdown("**Leakage scan summary**")
    st.json(summary)

final_out = next((e for e in sess_events if e.get("type") == "final_output"), None)
if final_out:
    st.markdown("**Final output**")
    st.json(final_out.get("body") or {})