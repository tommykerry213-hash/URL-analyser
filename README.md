# URL-analyser
# 🛡️ URL-analyser - SOC Grade Threat Scanner

A lightweight SOC Tier 1 tool to triage suspicious / malicious URLs. Built for speed, safety, and real SOC workflows.

Live Repo: https://github.com/tommykerry213-hash/URL-analyser

### What it does
This isn't just a regex checker - it's a 3-layer triage engine:

**1. 🎯 Heuristic Engine (`analyser.py`)**
- Detects XSS, SQLi, LFI, Command Injection payloads in URL
- Flags obfuscation: excessive encoding, hex, IP-based hosts, punycode
- MITRE ATT&CK: T1059, T1027, T1078

**2. 🧪 Safe Sandbox (`sandbox.py`)**
- Fetches URL safely: No JS execution, 5s timeout, 1MB limit, redirect tracking
- Extracts: final URL, page title, forms, iframes
- Detects obfuscated JavaScript (eval, atob, fromCharCode patterns)
- 100% safe - no browser execution

**3. 🦠 VirusTotal Intel (`virustotal.py`)**
- VT API v3 integration for reputation check
- Returns malicious count + full stats
- Graceful fallback if no API key

### Risk Scoring 0-100
- 0-34: 🟢 CLEAN
- 35-69: 🟡 SUSPICIOUS - Review in sandbox
- 70-100: 🔴 MALICIOUS - Block & Isolate

### Files in this repo
- `analyser.py` - Core detection
- `sandbox.py` - Safe fetch & DOM analysis
- `virustotal.py` - VT API client
- `utils.py` - Helpers (domain parsing, decoding)
- `streamlit_app.py` - Web UI for SOC analysts
- `requirements.txt` - Dependencies

### Run locally
```bash
pip install -r requirements.txt
python analyser.py "https://example.com/suspicious?token=xyz.exe"

# Or launch web UI:
streamlit run streamlit_app.py
