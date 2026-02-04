# scripts/dashboard.py
import os
import json
import hashlib
from typing import List, Optional, Tuple

import pandas as pd
import streamlit as st
import yaml

st.set_page_config(page_title="SentinelFlow Dashboard", layout="wide")

ZERO64 = "0" * 64


def canonical_json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def safe_load_json(path: str) -> Optional[dict]:
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def safe_load_jsonl(path: str) -> List[dict]:
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def read_config(path="config.yaml") -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def get_session_id(rec: dict) -> Optional[str]:
    return (rec.get("body") or {}).get("session_id")


def get_event_type(rec: dict) -> str:
    return str(rec.get("type") or "")


def get_event_ts(rec: dict) -> str:
    return str(rec.get("ts") or "")


def _expected_event_hash(r: dict) -> str:
    payload = {
        "ts": r.get("ts"),
        "type": r.get("type"),
        "body": r.get("body"),
        "prev_hash": r.get("prev_hash"),
        "session_prev_hash": r.get("session_prev_hash", ZERO64),
    }
    return sha256_str(canonical_json(payload))


def _expected_session_event_hash(r: dict) -> str:
    payload = {
        "ts": r.get("ts"),
        "type": r.get("type"),
        "body": r.get("body"),
        "session_prev_hash": r.get("session_prev_hash", ZERO64),
    }
    return sha256_str(canonical_json(payload))


def validate_global_chain(records: List[dict]) -> Tuple[bool, pd.DataFrame]:
    rows = []
    ok = True
    prev_event_hash = None

    for i, r in enumerate(records):
        prev_hash = r.get("prev_hash")
        event_hash = r.get("event_hash")

        expected = _expected_event_hash(r)
        hash_ok = None
        if event_hash:
            hash_ok = (expected == event_hash)

        link_ok = None
        if i == 0:
            link_ok = True
        else:
            if prev_hash is not None and prev_event_hash is not None:
                link_ok = (prev_hash == prev_event_hash)

        if (hash_ok is False) or (link_ok is False):
            ok = False

        rows.append({
            "i": i,
            "ts": get_event_ts(r),
            "type": get_event_type(r),
            "session_id": get_session_id(r),
            "hash_ok": hash_ok,
            "link_ok": link_ok,
            "prev_hash_prefix": (prev_hash or "")[:10],
            "event_hash_prefix": (event_hash or "")[:10],
        })
        prev_event_hash = event_hash or prev_event_hash

    return ok, pd.DataFrame(rows)


def validate_session_chain(records: List[dict], session_id: str) -> Tuple[bool, pd.DataFrame]:
    sess = [r for r in records if get_session_id(r) == session_id]
    rows = []
    ok = True
    prev_sess_hash = ZERO64

    for i, r in enumerate(sess):
        session_prev_hash = r.get("session_prev_hash", ZERO64)
        session_event_hash = r.get("session_event_hash")

        expected = _expected_session_event_hash(r)
        hash_ok = None
        if session_event_hash:
            hash_ok = (expected == session_event_hash)

        link_ok = (session_prev_hash == prev_sess_hash)

        if (hash_ok is False) or (link_ok is False):
            ok = False

        rows.append({
            "i": i,
            "ts": get_event_ts(r),
            "type": get_event_type(r),
            "hash_ok": hash_ok,
            "link_ok": link_ok,
            "session_prev_hash_prefix": (session_prev_hash or "")[:10],
            "session_event_hash_prefix": (session_event_hash or "")[:10],
        })
        prev_sess_hash = session_event_hash or prev_sess_hash

    return ok, pd.DataFrame(rows)


def load_eval_summary() -> Optional[dict]:
    return safe_load_json("reports/eval_summary.json")


def load_eval_cases() -> pd.DataFrame:
    if os.path.exists("reports/eval_cases.csv"):
        try:
            return pd.read_csv("reports/eval_cases.csv")
        except Exception:
            pass

    # fallback: jsonl
    for p in ["reports/eval_cases.jsonl", "reports/eval_results.jsonl", "reports/eval_details.jsonl"]:
        if os.path.exists(p):
            rows = safe_load_jsonl(p)
            if rows:
                return pd.DataFrame(rows)
    return pd.DataFrame()

def backfill_session_id_from_audit(df_cases: pd.DataFrame, records: List[dict]) -> pd.DataFrame:
    if df_cases is None or df_cases.empty:
        return df_cases

    # map query -> unique session_id if unique
    q_to_sessions = {}
    for r in records:
        body = r.get("body") or {}
        q = (body.get("query") or "").strip()
        sid = (body.get("session_id") or "").strip()
        if not q or not sid:
            continue
        q_to_sessions.setdefault(q, set()).add(sid)

    if "session_id" not in df_cases.columns:
        df_cases["session_id"] = ""

    def _fill(row):
        sid = str(row.get("session_id") or "").strip()
        if sid:
            return sid
        q = str(row.get("query") or "").strip()
        sids = sorted(list(q_to_sessions.get(q, set())))
        return sids[0] if len(sids) == 1 else ""

    df_cases["session_id"] = df_cases.apply(_fill, axis=1)
    return df_cases


def render_policy_panel(cfg: dict):
    st.subheader("Policy (config.yaml)")
    if not cfg:
        st.warning("config.yaml not found (or empty).")
        return

    policy = cfg.get("policy", {}) or {}
    intent_rules = policy.get("intent_rules", []) or []

    st.markdown("### Intent Rules")
    if intent_rules:
        df = pd.DataFrame([{
            "id": r.get("id"),
            "name": r.get("name"),
            "severity": r.get("severity"),
            "action": r.get("action"),
            "patterns_count": len(r.get("patterns") or []),
        } for r in intent_rules])
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No policy.intent_rules found.")

    st.markdown("### Full config")
    st.code(yaml.safe_dump(cfg, sort_keys=False), language="yaml")


def render_sentence_actions(sent_rows: List[dict], title: str):
    st.markdown(f"### {title}")
    if not sent_rows:
        st.info("No sentence-level rows.")
        return

    table = []
    for r in sent_rows:
        table.append({
            "sent_index": r.get("sent_index"),
            "decision": r.get("decision"),
            "reason": r.get("reason"),
            "leak_score": r.get("score"),
            "ground_score": r.get("ground_score"),
            "secret_id": r.get("secret_id"),
            "secret_title": r.get("secret_title"),
            "secret_category": r.get("secret_category"),
            "ground_doc_id": (r.get("ground_doc") or {}).get("doc_id") if r.get("ground_doc") else None,
            "ground_doc_title": (r.get("ground_doc") or {}).get("title") if r.get("ground_doc") else None,
            "text": r.get("text"),
        })
    df = pd.DataFrame(table)
    st.dataframe(df, use_container_width=True)

    parts = []
    for r in table:
        txt = r.get("text") or ""
        decision = (r.get("decision") or "allow").lower()
        meta = f"decision={decision} reason={r.get('reason')} leak={r.get('leak_score')} ground={r.get('ground_score')}"
        if decision in {"redact", "block"}:
            parts.append(
                f"<div style='margin:6px 0;'>"
                f"<mark>{txt}</mark><br/>"
                f"<span style='font-size:12px;color:#666;'>{meta}</span>"
                f"</div>"
            )
        else:
            parts.append(
                f"<div style='margin:6px 0;'>"
                f"{txt}<br/>"
                f"<span style='font-size:12px;color:#666;'>{meta}</span>"
                f"</div>"
            )
    st.markdown("\n".join(parts), unsafe_allow_html=True)


def main():
    st.title("SentinelFlow — Firewall + RAG + Evidence Chain + Evaluation")

    with st.sidebar:
        st.header("Paths")
        audit_path = st.text_input("audit_log.jsonl", value="data/audit/audit_log.jsonl")
        st.caption("Run: python scripts/demo_cases.py  (writes reports/eval_cases.csv + reports/eval_summary.json)")
        cfg = read_config("config.yaml")
        st.divider()
        render_policy_panel(cfg)

    records = safe_load_jsonl(audit_path)
    if not records:
        st.warning("No audit events found. Run run_rag_with_audit.py or demo_cases.py first.")
        st.stop()

    session_ids = [sid for sid in [get_session_id(r) for r in records] if sid]
    uniq_sessions = sorted(list(set(session_ids)))

    llm_calls = sum(1 for r in records if get_event_type(r) == "llm_response")
    intent_blocks = sum(1 for r in records if get_event_type(r) == "intent_precheck" and (r.get("body") or {}).get("blocked") is True)
    precheck_blocks = sum(1 for r in records if get_event_type(r) == "query_precheck" and (r.get("body") or {}).get("blocked") is True)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total events", len(records))
    c2.metric("Unique sessions", len(uniq_sessions))
    c3.metric("LLM calls", llm_calls)
    c4.metric("Intent blocks", intent_blocks)
    c5.metric("Precheck blocks", precheck_blocks)

    tabs = st.tabs(["Sessions", "Evaluation (demo_cases)", "Chain Debug"])

    # Sessions tab
    with tabs[0]:
        st.subheader("Session Viewer")
        selected = st.selectbox("Select session_id", uniq_sessions, index=max(0, len(uniq_sessions) - 1))
        sess = [r for r in records if get_session_id(r) == selected]

        st.markdown("### Timeline")
        timeline = []
        for r in sess:
            body = r.get("body") or {}
            summ = body.get("summary") or {}
            timeline.append({
                "ts": get_event_ts(r),
                "type": get_event_type(r),
                "query": body.get("query"),
                "blocked": body.get("blocked"),
                "decision": body.get("decision"),
                "blocked_by": body.get("blocked_by"),
                "leakage_flag": summ.get("leakage_flag") if summ else body.get("leakage_flag"),
                "trigger_reason": summ.get("trigger_reason") if summ else body.get("trigger_reason"),
            })
        st.dataframe(pd.DataFrame(timeline), use_container_width=True)

        def _find(tname: str) -> Optional[dict]:
            return next((r for r in sess if get_event_type(r) == tname), None)

        intent_ev = _find("intent_precheck")
        pre_ev = _find("query_precheck")
        retr_ev = _find("retrieve")
        ground_ev = _find("grounding_check")
        leak_ev = _find("leakage_scan")
        final_ev = _find("final_output")

        st.markdown("### Key Artifacts")
        col1, col2 = st.columns(2)
        with col1:
            if intent_ev:
                st.markdown("**intent_precheck**")
                st.json(intent_ev.get("body") or {})
            if pre_ev:
                st.markdown("**query_precheck**")
                st.json(pre_ev.get("body") or {})
            if retr_ev:
                st.markdown("**retrieve (top-k docs)**")
                docs = (retr_ev.get("body") or {}).get("docs") or []
                if docs:
                    st.dataframe(pd.DataFrame(docs), use_container_width=True)
                else:
                    st.info("No docs.")
        with col2:
            if ground_ev:
                st.markdown("**grounding_check**")
                st.json(ground_ev.get("body") or {})
            if leak_ev:
                st.markdown("**leakage_scan summary**")
                st.json((leak_ev.get("body") or {}).get("summary") or {})
            if final_ev:
                st.markdown("**final_output**")
                b = final_ev.get("body") or {}
                st.json(b)
                if b.get("final_answer"):
                    st.code(b["final_answer"])

        if leak_ev:
            srows = (leak_ev.get("body") or {}).get("sentences") or []
            render_sentence_actions(srows, "Sentence Actions (Leakage + Grounding)")

    # Evaluation tab
    with tabs[1]:
        st.subheader("Evaluation (from demo_cases.py)")
        summary = load_eval_summary()
        df_cases = load_eval_cases()
        df_cases = backfill_session_id_from_audit(df_cases, records)

        if summary:
            st.markdown("### Summary")
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("cases", summary.get("cases"))
            m2.metric("pass_rate", summary.get("pass_rate"))
            m3.metric("block_rate_hard", summary.get("block_rate_hard"))
            m4.metric("leak_escape_rate", summary.get("leak_escape_rate"))
            st.json(summary)
        else:
            st.info("No reports/eval_summary.json found yet. Run: python scripts/demo_cases.py")

        if df_cases is None or df_cases.empty:
            st.info("No reports/eval_cases.csv found yet. Run: python scripts/demo_cases.py")
        else:
            for col in ["case_id", "group", "expected", "outcome", "llm_called", "blocked_stage", "ok", "reason", "session_id"]:
                if col not in df_cases.columns:
                    df_cases[col] = None

            st.markdown("### Cases")
            only_fail = st.checkbox("Show only failures", value=True)
            groups = ["(all)"] + sorted([x for x in df_cases["group"].dropna().unique().tolist()])
            g = st.selectbox("Filter by group", groups)

            view = df_cases.copy()
            if only_fail:
                view = view[view["ok"] == False].copy()
            if g != "(all)":
                view = view[view["group"] == g].copy()

            st.dataframe(view, use_container_width=True)

            st.markdown("### Jump to session")
            candidates = view.dropna(subset=["session_id"])
            if not candidates.empty:
                sid = st.selectbox("Pick a failing session_id", candidates["session_id"].unique().tolist())
                st.caption("Copy this session_id, then go to the Sessions tab and select it.")
                st.code(str(sid))
            else:
                st.info("No session_id found in evaluation results. (demo_cases.py should write session_id per case)")

    # Chain Debug tab
    with tabs[2]:
        st.subheader("Chain Debug")
        mode = st.radio("Validation mode", options=["session", "global"], horizontal=True)

        if mode == "global":
            ok, df_val = validate_global_chain(records)
            st.success("Global chain OK ✅" if ok else "Global chain BROKEN ❌")
            st.dataframe(df_val, use_container_width=True)
        else:
            sid = st.selectbox("Pick session", uniq_sessions, index=max(0, len(uniq_sessions) - 1))
            ok, df_val = validate_session_chain(records, sid)
            st.success("Session chain OK ✅" if ok else "Session chain BROKEN ❌")
            st.dataframe(df_val, use_container_width=True)


if __name__ == "__main__":
    main()