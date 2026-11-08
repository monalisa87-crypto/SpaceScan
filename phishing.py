
from urllib.parse import urlparse
import ipaddress
import re


# ==========================================
# SPHERESCAN - PHISHING DETECTOR
# ==========================================

# Common phishing-related words
SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "password",
    "signin",
    "banking",
    "payment",
    "confirm",
    "wallet",
    "suspended"
]

# Common URL shortening services
URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "shorturl.at"
]

# Commonly impersonated brands and their real domains
BRANDS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "netflix": "netflix.com"
}


# ==========================================
# MAIN PHISHING DETECTION FUNCTION
# ==========================================

def detect_phishing(url):

    url = url.strip()

    # Check empty input
    if not url:
        return {
            "error": "Please enter a website URL."
        }

    # Check spaces
    if any(char.isspace() for char in url):
        return {
            "error": "URL cannot contain spaces."
        }

    # Add HTTPS if scheme is missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.hostname

    except ValueError:
        return {
            "error": "Invalid URL format."
        }

    if parsed.scheme not in ("http", "https") or not domain:
        return {
            "error": "Invalid website URL."
        }

    domain = domain.lower().rstrip(".")
    full_url = url.lower()

    # Store detection results
    findings = []
    score = 0

    # 1. Check IP address
    try:
        ipaddress.ip_address(domain)

        findings.append(
            "Website uses an IP address instead of a domain."
        )
        score += 25

    except ValueError:
        pass

    # 2. Check suspicious keywords in URL
    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in full_url:
            found_keywords.append(keyword)

    if found_keywords:
        findings.append(
            "Suspicious keywords found: "
            + ", ".join(found_keywords)
        )
        score += min(len(found_keywords) * 5, 20)

    # 3. Check URL shorteners
    if domain in URL_SHORTENERS:
        findings.append(
            "URL uses a shortening service."
        )
        score += 15

    # 4. Check brand impersonation
    for brand, real_domain in BRANDS.items():

        if brand in domain:
            if (
                domain != real_domain
                and not domain.endswith("." + real_domain)
            ):
                findings.append(
                    "Possible " + brand.title()
                    + " brand impersonation."
                )
                score += 30

    # 5. Check excessive hyphens
    if domain.count("-") >= 3:
        findings.append(
            "Domain contains many hyphens."
        )
        score += 10

    # 6. Check excessive subdomains
    if len(domain.split(".")) > 4:
        findings.append(
            "Domain contains many subdomains."
        )
        score += 10

    # 7. Check @ symbol
    if "@" in parsed.netloc:
        findings.append(
            "URL contains an @ symbol."
        )
        score += 20

    # Limit score
    score = min(score, 100)

    # Determine phishing suspicion level
    if score <= 20:
        level = "LOW"

    elif score <= 50:
        level = "MEDIUM"

    else:
        level = "HIGH"

    return {
        "url": url,
        "domain": domain,
        "score": score,
        "level": level,
        "findings": findings,
        "is_suspicious": score > 20
    }


# ==========================================
# DISPLAY PHISHING REPORT
# ==========================================

def display_phishing_report(result):

    print("\n" + "=" * 45)
    print("       SPHERESCAN PHISHING DETECTOR")
    print("=" * 45)

    # Handle invalid URLs
    if "error" in result:

        print("\nINVALID URL!")
        print(result["error"])
        print("\nPlease enter a valid website address.")

        print("=" * 45)
        return

    print("\nWebsite:", result["url"])
    print("Domain:", result["domain"])

    print("\nPhishing Suspicion Score:",
          str(result["score"]) + "/100")

    print("Suspicion Level:", result["level"])

    print("\n--- DETECTION RESULTS ---")

    if result["findings"]:

        for finding in result["findings"]:
            print("[WARNING]", finding)

    else:
        print("No common phishing indicators detected.")

    print("\n--- FINAL ASSESSMENT ---")

    if result["level"] == "HIGH":
        print("High suspicion: Further security checks are recommended.")

    elif result["level"] == "MEDIUM":
        print("Medium suspicion: Inspect this website carefully.")

    else:
        print("Low suspicion: Few common indicators were detected.")

    print("\nIMPORTANT:")
    print("This is a heuristic detector, not a verified")
    print("phishing classification system.")
    print("A low score does not guarantee website safety.")

    print("=" * 45)


# ==========================================
# MAIN PROGRAM
# ==========================================

if __name__ == "__main__":

    website = input("\nEnter a website URL to check: ")

    result = detect_phishing(website)

    display_phishing_report(result)
