import requests
import socket
import ssl
import re
import whois
from urllib.parse import urlparse
from utils import risk_score, expand_short_url

THREAT_FEEDS = [
    "https://openphish.com/feed.txt",
    "https://phishunt.io/feed.txt"
]

def check_domain_reputation(domain):
    for feed in THREAT_FEEDS:
        try:
            data = requests.get(feed, timeout=5).text
            if domain in data:
                return False, f"Domain {domain} found in {feed}"
        except Exception:
            pass
    return True, "Domain not found in threat feeds"

def check_ssl_certificate(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return True, f"Valid SSL certificate issued by {cert['issuer']}"
    except Exception as e:
        return False, f"SSL check failed: {e}"

def heuristic_analysis(url):
    suspicious_patterns = []
    if re.search(r"\d{1,3}(\.\d{1,3}){3}", url):
        suspicious_patterns.append("IP address in URL")
    if "-" in urlparse(url).netloc:
        suspicious_patterns.append("Hyphenated domain")
    if len(urlparse(url).netloc.split(".")) > 3:
        suspicious_patterns.append("Excessive subdomains")
    return suspicious_patterns

def analyse_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    # Expand shorteners
    final_url = expand_short_url(url)
    if final_url != url:
        print(f"Expanded short URL → {final_url}")

    # Reputation
    rep_ok, rep_msg = check_domain_reputation(domain)

    # SSL
    ssl_ok, ssl_msg = check_ssl_certificate(domain)

    # Heuristics
    heuristics = heuristic_analysis(url)

    # WHOIS
    try:
        w = whois.whois(domain)
        domain_age = "Unknown"
        if w.creation_date:
            domain_age = (w.expiration_date - w.creation_date).days
    except Exception:
        domain_age = "WHOIS lookup failed"

    score = risk_score(rep_ok, ssl_ok, heuristics, domain_age)

    return {
        "url": url,
        "final_url": final_url,
        "domain": domain,
        "reputation": rep_msg,
        "ssl": ssl_msg,
        "heuristics": heuristics,
        "domain_age": domain_age,
        "risk_score": score
    }

if __name__ == "__main__":
    test_url = input("Enter URL to analyse: ")
    result = analyse_url(test_url)
    print(result)
