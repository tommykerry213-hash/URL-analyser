import requests

def expand_short_url(url):
    try:
        r = requests.head(url, allow_redirects=True, timeout=5)
        return r.url
    except Exception:
        return url

def risk_score(rep_ok, ssl_ok, heuristics, domain_age):
    score = 100
    if not rep_ok:
        score -= 40
    if not ssl_ok:
        score -= 20
    if heuristics:
        score -= len(heuristics) * 10
    if isinstance(domain_age, int) and domain_age < 180:
        score -= 20
    return max(score, 0)
