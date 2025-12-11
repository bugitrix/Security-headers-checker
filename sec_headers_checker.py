# sec_headers_checker.py
# Helper used by the Flask app. Defines run_check(target) that returns a report dict.

import requests
from urllib.parse import urlparse

HEADER_DB = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "description": "Instructs browsers to only use HTTPS for this domain for a period.",
        "impact": "Without HSTS, users may be vulnerable to downgrade and MitM attacks.",
        "remediation": "Serve 'Strict-Transport-Security' over HTTPS with a suitable 'max-age'.",
        "severity": "high",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "description": "Controls which sources of content (scripts, images, styles) are allowed.",
        "impact": "Missing CSP increases XSS risk.",
        "remediation": "Implement a restrictive CSP that whitelists trusted sources.",
        "severity": "high",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "description": "Prevents the site from being embedded in frames/iframes on other origins.",
        "impact": "Without it, the site may be vulnerable to clickjacking-like UI attacks.",
        "remediation": "Return 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
        "severity": "medium",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "description": "Stops browsers from sniffing MIME types.",
        "impact": "Without it, browsers might run content as a different type.",
        "remediation": "Return 'X-Content-Type-Options: nosniff'.",
        "severity": "medium",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "description": "Controls what referrer information is sent when navigating away.",
        "impact": "No policy may leak sensitive URL/query information to third parties.",
        "remediation": "Set a restrictive policy like 'no-referrer' or 'strict-origin-when-cross-origin'.",
        "severity": "low",
    },
    "permissions-policy": {
        "name": "Permissions-Policy (Feature-Policy)",
        "description": "Controls access to browser features like camera, geolocation.",
        "impact": "Without it, features may be available when not desired.",
        "remediation": "Disable unused features, e.g. 'geolocation=()'.",
        "severity": "low",
    },
    "cross-origin-opener-policy": {
        "name": "Cross-Origin-Opener-Policy (COOP)",
        "description": "Helps isolate browsing contexts to reduce cross-origin leaks.",
        "impact": "Missing COOP may increase risk of certain side-channel attacks.",
        "remediation": "Consider 'Cross-Origin-Opener-Policy: same-origin'.",
        "severity": "low",
    },
    "cross-origin-embedder-policy": {
        "name": "Cross-Origin-Embedder-Policy (COEP)",
        "description": "Controls loading of cross-origin resources unless allowed by CORS.",
        "impact": "Without it, some isolation guarantees are weaker.",
        "remediation": "Consider 'Cross-Origin-Embedder-Policy: require-corp' if needed.",
        "severity": "low",
    },
    "expect-ct": {
        "name": "Expect-CT",
        "description": "Helps detect misissued TLS certificates.",
        "impact": "Missing Expect-CT reduces visibility into certificate issues.",
        "remediation": "Use with a reporting endpoint if you understand implications.",
        "severity": "low",
    },
}

def normalize_target(target: str) -> str:
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    if not parsed.netloc:
        raise ValueError("Invalid target")
    return f"{parsed.scheme}://{parsed.netloc}"

def fetch_headers(url: str, timeout: int = 10):
    headers = {"User-Agent": "sec-headers-web/1.0"}
    resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=True)
    return resp

def analyze_response(resp):
    lower_map = {k.lower(): v for k, v in resp.headers.items()}
    found = {}
    missing = {}
    for key, meta in HEADER_DB.items():
        if key in lower_map:
            found[key] = {"value": lower_map[key], "meta": meta}
        else:
            missing[key] = {"meta": meta}

    # simple cookie capture
    set_cookie = resp.headers.get("Set-Cookie")
    cookie_info = []
    if set_cookie:
        # If multiple Set-Cookie headers exist, requests may return a single string; keep raw.
        cookie_info = resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else [set_cookie]

    return {
        "status_code": resp.status_code,
        "final_url": resp.url,
        "found": found,
        "missing": missing,
        "set_cookie": cookie_info,
    }

def run_check(target: str, timeout: int = 10):
    """
    Public function used by app.py
    Give a domain or URL like "example.com" or "https://example.com"
    Returns the report dict (as above).
    """
    url = normalize_target(target)
    resp = fetch_headers(url, timeout=timeout)
    return analyze_response(resp)
