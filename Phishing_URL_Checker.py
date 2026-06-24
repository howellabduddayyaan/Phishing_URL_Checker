# ============================
# === Phishing URL Checker ===
# ============================

import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update",
    "bank", "password", "confirm"
]

def is_ip(address):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", address) is not None

def analyze_url(url):
    print(f"\nAnalyzing: {url}")

    score = 0
    parsed = urlparse(url)

    domain = parsed.netloc.lower()
    path = parsed.path.lower()

