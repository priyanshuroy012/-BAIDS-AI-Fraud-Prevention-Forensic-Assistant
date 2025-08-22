# =============================
# app.py (Hackathon Enhanced)
# =============================
# BAIDS – AI Fraud Prevention & Forensic Assistant (Wildcard Track)
# New: Explainability (XAI), OSINT hooks, Gauge, Timeline (patched to read forensic .jsonl logs with auto-refresh), Map, Simulator, PDF Report

import json
import io
import random
import string
import os
from datetime import datetime

import pandas as pd
import streamlit as st

from hybrid_predictor import hybrid_predict

try:
    import plotly.graph_objects as go
except Exception:
    go = None

try:
    import folium
    from streamlit_folium import st_folium
except Exception:
    folium = None
    st_folium = None

st.set_page_config(page_title="BAIDS – Fraud Validator (Hackathon Edition)", layout="wide")

# ----------------------------
# Helpers
# ----------------------------

def _now_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _rand_id(prefix="EV"):  # evidence / attempt id
    return f"{prefix}-{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"


def make_gauge(score: float):
    if go is None:
        st.progress(min(max(int(score), 0), 100), text=f"Risk Score: {score:.1f}")
        return
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": " / 100"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"thickness": 0.25},
                "steps": [
                    {"range": [0, 30], "color": "#2ecc71"},
                    {"range": [30, 60], "color": "#f1c40f"},
                    {"range": [60, 100], "color": "#e74c3c"},
                ],
            },
            title={"text": "Final Risk"},
        )
    )
    fig.update_layout(height=280, margin=dict(l=10, r=10, t=40, b=10))
    st.plotly_chart(fig, use_container_width=True)


def try_geoplot(lat, lon, label="IP Geo"):
    if folium is None or st_folium is None or lat is None or lon is None:
        return
    m = folium.Map(location=[lat, lon], zoom_start=4)
    folium.Marker([lat, lon], tooltip=label).add_to(m)
    st_folium(m, width=500, height=320)


def safe_number(x, scale_to_100=False):
    try:
        val = float(x)
        return max(0.0, min(100.0, val * 100 if scale_to_100 else val))
    except Exception:
        return 0.0


def run_osint_checks(login_event: dict) -> dict:
    signals = {"notes": []}
    try:
        email = login_event.get("email") or login_event.get("user", {}).get("email")
        if email and "@" in email:
            domain = email.split("@")[-1].lower()
            if domain in {"mailinator.com", "tempmail.com", "10minutemail.com"}:
                signals["notes"].append("Disposable email domain detected")
        ip = login_event.get("ip") or login_event.get("network", {}).get("ip")
        if ip and ip.count(".") == 3:
            last_oct = int(ip.split(".")[-1])
            if last_oct > 200:
                signals["notes"].append("High-risk IP reputation (mock)")
    except Exception as e:
        signals["notes"].append(f"OSINT error: {e}")
    return signals


def make_pdf_report(verdict: dict, login_event: dict, osint: dict) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.pdfgen import canvas
    except Exception:
        buf = io.StringIO()
        buf.write("BAIDS – Fraud Report\n")
        buf.write(f"Generated: {_now_iso()}\n\n")
        buf.write(json.dumps(verdict, indent=2))
        return buf.getvalue().encode()

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    w, h = A4
    y = h - 2 * cm
    c.setFont("Helvetica", 12)
    c.drawString(2 * cm, y, "BAIDS – Fraud Prevention & Forensic Assistant")
    y -= 1 * cm
    c.setFont("Helvetica", 10)
    c.drawString(2 * cm, y, f"Generated: {_now_iso()}")
    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer.read()

# ----------------------------
# Sidebar Controls
# ----------------------------
with st.sidebar:
    st.header("⚙️ Controls")
    profile = st.selectbox("Risk Profile", ["Default", "Conservative", "Aggressive"], index=0)
    enable_osint = st.checkbox("Enable OSINT checks (mock)", value=True)

# ----------------------------
# Main Header
# ----------------------------
st.title("🛡️ BAIDS – AI Fraud Prevention & Forensic Assistant")
st.caption("Hybrid Rule + ML + OSINT • Explainable • Report-ready")

uploaded_file = st.file_uploader("Upload a login attempt JSON", type=["json"])

login_event = None
if uploaded_file:
    try:
        login_event = json.load(uploaded_file)
    except Exception as e:
        st.error(f"Invalid JSON file: {e}")

if not login_event:
    st.info("Upload a JSON or run the Simulator/API to generate forensic logs.")

# ----------------------------
# Tabs UI
# ----------------------------
summary_tab, breakdown_tab, osint_tab, timeline_tab, report_tab = st.tabs([
    "📊 Summary", "🔍 Breakdown", "🌐 OSINT", "🕒 Timeline & Map", "📑 Report",
])

if login_event:
    result = hybrid_predict(login_event, profile_name=profile)
    osint = run_osint_checks(login_event) if enable_osint else {"notes": ["OSINT disabled"]}

    with summary_tab:
        st.subheader("Overall Verdict")
        st.json(result)
        scaled = safe_number(result.get("final_risk_score"), scale_to_100=True)
        make_gauge(scaled)

    with breakdown_tab:
        st.subheader("Explainability")
        st.json(result.get("flags", {}))

    with osint_tab:
        st.subheader("OSINT Signals (mock)")
        st.json(osint)

    with report_tab:
        st.subheader("Generate Forensic Report")
        report_bytes = make_pdf_report(result, login_event, osint)
        fname = f"BAIDS_Report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        st.download_button("📥 Download Report", data=report_bytes, file_name=fname, mime="application/pdf")

# ----------------------------
# Patched Timeline Tab – reads forensic .jsonl logs with auto-refresh
# ----------------------------
with timeline_tab:
    st.subheader("Attempts Timeline (from forensic logs)")

    auto_refresh = st.checkbox("🔄 Auto-refresh every 5s", value=False)
    if auto_refresh:
        import time
        st.experimental_rerun_interval = 5  # rerun app every 5s (streamlit >=1.40)

    log_dir = "forensics_logs"
    today_file = os.path.join(log_dir, f"{datetime.utcnow().date()}.jsonl")
    rows = []
    if os.path.exists(today_file):
        with open(today_file, "r") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                    rows.append({
                        "ts": rec.get("ts"),
                        "verdict": rec.get("result", {}).get("verdict"),
                        "score": rec.get("result", {}).get("final_risk_score"),
                        "email": (rec.get("event", {}).get("user", {}) or {}).get("email"),
                        "ip": (rec.get("event", {}).get("network", {}) or {}).get("ip"),
                    })
                except:
                    continue
    if rows:
        df = pd.DataFrame(rows)
        st.dataframe(df.tail(20), use_container_width=True)
    else:
        st.info("No forensic log entries found yet. Run simulator.py with the Flask API.")
