# =============================
# app.py (Hackathon Enhanced – Stable Map + Sidebar Filters + Auto-load Tabs)
# =============================

import json
import io
import random
import string
import os
import hashlib
from datetime import datetime

import pandas as pd
import streamlit as st

from hybrid_predictor import hybrid_predict

try:
    import plotly.graph_objects as go
    import plotly.express as px
except Exception:
    go = None
    px = None

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

# Stable mock geolocation per IP using hash

def ip_to_coords(ip: str):
    try:
        h = int(hashlib.sha256(ip.encode()).hexdigest(), 16)
        lat = (h % 180) - 90   # -90 to +90
        lon = ((h // 180) % 360) - 180  # -180 to +180
        return float(lat), float(lon)
    except:
        return 0.0, 0.0

# ----------------------------
# Sidebar Controls (Uploader + Filters)
# ----------------------------
with st.sidebar:
    st.header("⚙️ Controls")
    profile = st.selectbox("Risk Profile", ["Default", "Conservative", "Aggressive"], index=0)
    enable_osint = st.checkbox("Enable OSINT checks (mock)", value=True)
    uploaded_file = st.file_uploader("📂 Upload a login attempt JSON", type=["json"])

    st.markdown("---")
    st.subheader("Filters for Timeline")
    min_score, max_score = st.slider("Risk score range", 0, 100, (0, 100))
    verdict_filter = st.multiselect("Verdict", [])  # dynamically updated later
    email_filter = st.text_input("Email contains")
    ip_filter = st.text_input("IP contains")

# ----------------------------
# Load Logs
# ----------------------------
log_dir = "forensics_logs"
today_file = os.path.join(log_dir, f"{datetime.utcnow().date()}.jsonl")
rows = []
if os.path.exists(today_file):
    with open(today_file, "r") as f:
        for line in f:
            try:
                rec = json.loads(line)
                rows.append(rec)
            except:
                continue

df_logs = pd.DataFrame([{
    "ts": r.get("ts"),
    "verdict": r.get("result", {}).get("verdict"),
    "score": r.get("result", {}).get("final_risk_score"),
    "email": (r.get("event", {}).get("user", {}) or {}).get("email"),
    "ip": (r.get("event", {}).get("network", {}) or {}).get("ip"),
} for r in rows]) if rows else pd.DataFrame()

# Update verdict filter dynamically
if not df_logs.empty:
    st.sidebar.multiselect("Verdict", options=df_logs["verdict"].dropna().unique(), default=list(df_logs["verdict"].dropna().unique()), key="verdict_filter")

# ----------------------------
# Load Current Event (from upload or latest log)
# ----------------------------
login_event = None
result = None
osint = None

if uploaded_file:
    try:
        login_event = json.load(uploaded_file)
        result = hybrid_predict(login_event, profile_name=profile)
        osint = run_osint_checks(login_event) if enable_osint else {"notes": ["OSINT disabled"]}
    except Exception as e:
        st.error(f"Invalid JSON file: {e}")

elif rows:
    last_entry = rows[-1]
    login_event = last_entry.get("event", {})
    result = last_entry.get("result", {})
    osint = run_osint_checks(login_event) if enable_osint else {"notes": ["OSINT disabled"]}

# ----------------------------
# Main Header
# ----------------------------
st.title("🛡️ BAIDS – AI Fraud Prevention & Forensic Assistant")
st.caption("Hybrid Rule + ML + OSINT • Explainable • Report-ready")

# ----------------------------
# Tabs UI
# ----------------------------
summary_tab, breakdown_tab, osint_tab, timeline_tab, report_tab = st.tabs([
    "📊 Summary", "🔍 Breakdown", "🌐 OSINT", "🕒 Timeline & Map", "📑 Report",
])

if login_event and result is not None:
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
# Timeline Tab – filters, charts, map
# ----------------------------
with timeline_tab:
    st.subheader("Attempts Timeline (from forensic logs)")
    if df_logs.empty:
        st.info("No forensic log entries found yet. Run simulator.py with the Flask API.")
    else:
        df = df_logs.copy()
        
        # Apply filters (optional)
        df = df[df["score"].between(min_score, max_score)]
        verdict_selected = st.session_state.get("verdict_filter", [])
        if verdict_selected:
            df = df[df["verdict"].isin(verdict_selected)]
        if email_filter:
            df = df[df["email"].fillna("").str.contains(email_filter, case=False)]
        if ip_filter:
            df = df[df["ip"].fillna("").str.contains(ip_filter, case=False)]

        # Summary metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Attempts", len(df))
        fraud_count = (df["verdict"] == "Fraud").sum()
        col2.metric("Fraudulent Attempts", fraud_count)
        avg_score = df["score"].mean() if not df["score"].isna().all() else 0
        col3.metric("Avg Risk Score", f"{avg_score:.1f}")

        # Data table
        st.dataframe(df.tail(20), use_container_width=True)

        if px is not None:
            st.subheader("📈 Risk Score Trend")
            try:
                chart_df = df.dropna(subset=["score"])
                chart_df["ts"] = pd.to_datetime(chart_df["ts"])
                fig = px.line(chart_df, x="ts", y="score", color="verdict", markers=True, title="Risk Scores Over Time")
                st.plotly_chart(fig, use_container_width=True)
            except Exception as e:
                st.warning(f"Could not plot line chart: {e}")

            st.subheader("📊 Fraud vs Legit Distribution")
            try:
                fig2 = px.pie(df, names="verdict", title="Fraud vs Legit Attempts")
                st.plotly_chart(fig2, use_container_width=True)
            except Exception as e:
                st.warning(f"Could not plot pie chart: {e}")

        # 🌍 Map visualization (stable geolocation from IP hash)
        if folium is not None and st_folium is not None and not df.empty:
            st.subheader("🌍 Login Attempt Geomap")
            m = folium.Map(location=[20,0], zoom_start=2)
            for _, row in df.iterrows():
                ip = row.get("ip") or "0.0.0.0"
                lat, lon = ip_to_coords(ip)
                verdict = row["verdict"]
                color = "green" if verdict == "Legit" else "red"
                folium.CircleMarker(
                    [lat, lon], radius=6, color=color, fill=True, fill_opacity=0.7,
                    tooltip=f"{row['email']} ({verdict}, score={row['score']:.1f}, ip={ip})"
                ).add_to(m)
            st_folium(m, width=700, height=400)







