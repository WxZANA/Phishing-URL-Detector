import sys
import re
from urllib.parse import urlparse

def analyze_url(url):

    score = 0
    reasons = []

    parsed = urlparse(url)
    domain = parsed.netloc

    # rule 1: URL length
    if len(url) > 75:
        score += 1
        reasons.append("URL is unusually long")

    # rule 2: many subdomains
    if domain.count(".") > 3:
        score += 1
        reasons.append("Too many subdomains")

    # rule 3: IP address instead of domain
    if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 2
        reasons.append("Uses IP address instead of domain name")

    # rule 4: suspicious words
    suspicious_words = [
        "login",
        "verify",
        "account",
        "secure",
        "update",
        "bank",
        "password"
    ]

    for word in suspicious_words:
        if word in url.lower():
            score += 1
            reasons.append(f"Contains suspicious keyword: {word}")
            break

    return score, reasons


def main():

    if len(sys.argv) != 2:
        print("Usage: python main.py <url>")
        return

    url = sys.argv[1]

    print("\nAnalyzing URL...\n")

    score, reasons = analyze_url(url)

    print("URL:", url)
    print("Risk score:", score)

    if score == 0:
        print("Result: Likely safe\n")
    elif score <= 2:
        print("Result: Possibly suspicious\n")
    else:
        print("Result: Likely phishing\n")

    if reasons:
        print("Reasons:")
        for r in reasons:
            print("-", r)


if __name__ == "__main__":
    main()