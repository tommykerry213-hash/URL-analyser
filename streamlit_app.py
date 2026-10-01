import streamlit as st
from analyser import analyse_url
from sandbox import safe_fetch
from virustotal import get_vt_report

st.set_page_config(page_title="URL Threat Scanner - SOC", page_icon="🛡️", layout="wide")

st.title("🛡️ URL-analyser - SOC Edition")
st.caption("Client-side heuristics + Safe Sandbox + VirusTotal - 100% SOC ready")

url = st.text_input("Enter URL to scan", placeholder="https://suspicious-update.net/login?token=xyz.exe")

if st.button("⚡ SCAN NOW", type="primary"):
    if not url:
        st.warning("Paste a URL first")
        st.stop()

    col1, col2, col3 = st.columns(3)

    # 1. Heuristic
    with col1:
        st.subheader("🎯 Heuristic Analysis")
        result = analyse_url(url)
        score = result.get('score', 0)
        st.metric("Risk Score", f"{score}/100")
        for flag in result.get('flags', []):
            st.write(f"- {flag}")

    # 2. Sandbox
    with col2:
        st.subheader("🧪 Sandbox Fetch")
        with st.spinner("Fetching safely..."):
            sb = safe_fetch(url)
        if sb.get("error"):
            st.error(sb["error"])
        else:
            st.success(f"Final URL: {sb['final_url'][:60]}")
            st.write(f"Title: `{sb['title']}`")
            if sb["forms"]:
                st.warning(f"Found {len(sb['forms'])} form(s) - Possible credential harvest")
            if sb["has_obfuscated_js"]:
                st.error("🔴 Obfuscated JavaScript detected!")
            if sb["iframes"]:
                st.write(f"Iframes: {len(sb['iframes'])}")

    # 3. VirusTotal
    with col3:
        st.subheader("🦠 VirusTotal")
        with st.spinner("Checking VT..."):
            vt = get_vt_report(url)
        if "error" in vt:
            st.info(vt["error"])
        else:
            st.metric("Malicious hits", vt.get("malicious", 0))
            st.json(vt.get("raw_stats", {}))

    # Final Verdict
    st.divider()
    final_score = result.get('score', 0)
    if 'malicious' in vt and isinstance(vt['malicious'], int):
        final_score += vt['malicious'] * 5

    if final_score >= 70:
        st.error(f"### 🔴 MALICIOUS - {final_score}/100 - BLOCK & ISOLATE [MITRE T1078, T1027]")
    elif final_score >= 35:
        st.warning(f"### 🟡 SUSPICIOUS - {final_score}/100 - SANDBOX & REVIEW")
    else:
        st.success(f"### 🟢 CLEAN - {final_score}/100")

    st.download_button(
        "📄 Export Report", 
        data=f"URL: {url}\nScore: {final_score}\nHeuristics: {result}\nSandbox: {sb}\nVT: {vt}", 
        file_name="url-threat-report.txt"
    )
