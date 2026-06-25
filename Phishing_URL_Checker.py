# ============================
# === Phishing URL Checker ===
# ============================

from urllib.parse import urlparse

Suspicious_Keywords = [
                    "login", "verify","secure", "account", 
                    "update","bank", "password", "confirm"
                    ]

# _________________________________________________________________________________________________

def is_ip(address):
    parts = address.split(".")
    
    if len(parts) != 4:
        return False

    for part in parts:
        if not part.isdigit():
            return False

        if not 0 <= int(part) <= 255:
            return False

    return True

# _________________________________________________________________________________________________

def analyze_url(url):
    print(f"\nAnalyzing: {url}")

    score = 0
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

# _________________________________________________________________________________________________

    if is_ip(domain) :
        print("[!] Uses IP address instead of domain")
        score += 2

# _________________________________________________________________________________________________

    if "@" in parsed.geturl() :
        print("[!] Contains '@' (Possible redirect trick)")
        score += 1

# _________________________________________________________________________________________________

    if len(url) > 75 :
        print("[!] URL is unusually long")
        score += 1
    
# _________________________________________________________________________________________________

    for keyword in Suspicious_Keywords:
        if keyword in url.lower():
            print(f"[!] Suspicious keyword found : {keyword}")
            score += 1
            
# _________________________________________________________________________________________________

    if domain.count(".") > 3 :
        print("[!] Too many subdomains")
        score += 1
        
# _________________________________________________________________________________________________

    if parsed.scheme != "https":
        print("[!] Not using HTTPS")
        score += 1
        
# _________________________________________________________________________________________________

    if "-" in domain:
        print("[!] Domain contains hyphen")
        score += 1

# _________________________________________________________________________________________________

    print("\nRisk Score : ", score)

    if score >= 4 :
        print("!!! HIGH RISK : Possible Phishing URL")
        
    elif score >= 2 :
        print("!! MEDIUM RISK : Proceed with caution")
        
    else:
        print("! LOW RISK : No threats within the URL detected")
        
# _________________________________________________________________________________________________

if __name__ == "__main__":
    while True:
        url = input("\nEnter URL or exit :")
        if url.lower() == "exit":
            break
        analyze_url(url)
        
# _________________________________________________________________________________________________
