import os
import time
import hashlib
import requests
import base64

VT_API_KEY = os.getenv("VT_API_KEY")  # NEVER hardcode - use env var
VT_URL = "https://www.virustotal.com/api/v3"

def get_vt_report(url: str) -> dict:
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set - add to .env or Streamlit secrets"}
    
    # VT needs base64 url-safe id
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        # 1. Get existing report
        r = requests.get(f"{VT_URL}/urls/{url_id}", headers=headers, timeout=10)
        
        if r.status_code == 404:
            # 2. Submit if not found
            r = requests.post(f"{VT_URL}/urls", headers=headers, data={"url": url}, timeout=10)
            if r.status_code != 200:
                return {"error": f"VT submit failed: {r.status_code}"}
            # Wait for scan
            time.sleep(15)
            r = requests.get(f"{VT_URL}/urls/{url_id}", headers=headers, timeout=10)

        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "reputation": data.get("reputation", 0),
            "categories": data.get("categories", {}),
            "raw_stats": stats
        }
    except Exception as e:
        return {"error": f"VT API error: {str(e)[:150]}"}
