import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re

# SOC safety controls
TIMEOUT = 5
MAX_SIZE = 1_000_000  # 1MB max, stops zip bombs
MAX_REDIRECTS = 2
HEADERS = {"User-Agent": "SOC-Scanner/1.0 (Security Research)"}

def safe_fetch(url: str) -> dict:
    result = {
        "final_url": url,
        "status_code": None,
        "title": "",
        "forms": [],
        "iframes": [],
        "has_obfuscated_js": False,
        "error": None
    }
    
    # Basic validation
    parsed = urlparse(url)
    if parsed.scheme not in ["http", "https"]:
        result["error"] = "Invalid scheme - only http/https allowed"
        return result

    try:
        # No JS execution - requests only, no selenium
        resp = requests.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=True,
            verify=True,  # check SSL
            stream=True
        )
        resp.history = resp.history[:MAX_REDIRECTS]
        result["final_url"] = resp.url
        result["status_code"] = resp.status_code

        # Size check
        content = resp.content[:MAX_SIZE]
        if len(resp.content) > MAX_SIZE:
            result["error"] = "Content too large - possible payload"

        soup = BeautifulSoup(content, 'html.parser')
        result["title"] = soup.title.string.strip() if soup.title and soup.title.string else ""

        # Extract risky elements
        for form in soup.find_all("form"):
            result["forms"].append({
                "action": form.get("action", ""),
                "has_password": bool(form.find("input", {"type": "password"}))
            })
        
        for iframe in soup.find_all("iframe"):
            src = iframe.get("src", "")
            if src:
                result["iframes"].append(src)

        # Detect obfuscated JS - common in malware
        scripts = " ".join([s.get_text() for s in soup.find_all("script")])
        if re.search(r"eval\(atob|fromCharCode|unescape.*%u|document\.write\(.*atob", scripts, re.I):
            result["has_obfuscated_js"] = True

    except requests.exceptions.SSLError:
        result["error"] = "Invalid / Self-signed SSL - Phishing indicator"
    except requests.exceptions.Timeout:
        result["error"] = "Timeout - Possible C2 dead drop"
    except Exception as e:
        result["error"] = f"Fetch failed safely: {str(e)[:100]}"

    return result
