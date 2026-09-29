import re
from email import policy
from email.parser import Parser
from urllib.parse import urlparse

URGENT_WORDS = {
    "urgent", "immediately", "verify", "suspended", "password",
    "click now", "act now", "confirm", "account locked"
}

def analyze_email(raw_email):
    msg = Parser(policy=policy.default).parsestr(raw_email)

    headers = {
        "From": msg.get("From", ""),
        "Return-Path": msg.get("Return-Path", ""),
        "Received": msg.get("Received", ""),
        "Authentication-Results": msg.get("Authentication-Results", "")
    }

    body = msg.get_body(preferencelist=("plain", "html"))
    body_text = body.get_content() if body else msg.get_content()

    score = 0
    indicators = []

    # Header checks
    if headers["From"] and headers["Return-Path"]:
        from_domain = re.search(r'@([\w.-]+)', headers["From"])
        return_domain = re.search(r'@([\w.-]+)', headers["Return-Path"])
        if from_domain and return_domain and from_domain.group(1).lower() != return_domain.group(1).lower():
            score += 25
            indicators.append("From and Return-Path domains do not match.")

    auth = headers["Authentication-Results"].lower()
    if "spf=fail" in auth:
        score += 20
        indicators.append("SPF authentication failed.")
    if "dkim=fail" in auth:
        score += 20
        indicators.append("DKIM authentication failed.")

    # Body checks
    urls = re.findall(r'https?://[^\s<>"\']+', body_text)
    for url in urls:
        domain = urlparse(url).netloc.lower()
        if domain.endswith(".example.com") or domain.endswith(".example.org"):
            continue
        score += 10
        indicators.append(f"External link detected: {domain}")

    lower_body = body_text.lower()
    found_urgent = [word for word in URGENT_WORDS if word in lower_body]
    if found_urgent:
        score += min(20, len(found_urgent) * 5)
        indicators.append("Urgency/action language: " + ", ".join(sorted(found_urgent)))

    score = min(score, 100)
    if score >= 60:
        risk = "HIGH"
    elif score >= 30:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return score, risk, indicators, headers, body_text

if __name__ == "__main__":
    sample_email = """From: Security Team <security@company.example>
Return-Path: <mailer@different.example>
Authentication-Results: spf=fail; dkim=fail
Subject: Urgent account verification

Your account is suspended. Verify your password immediately:
https://secure-login.example.org/verify
"""

    score, risk, indicators, headers, body = analyze_email(sample_email)

    print("=== EMAIL RISK ANALYZER ===")
    print(f"Risk Score: {score}/100")
    print(f"Risk Level: {risk}")
    print("\nIndicators:")
    for item in indicators:
        print(f"- {item}")
