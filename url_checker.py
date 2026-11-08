
from urllib.parse import urlparse
import ipaddress
import re


# =====================================
# SPHERESCAN - URL CHECKER
# =====================================

def check_url(url):

    url = url.strip()

    # 1. Check empty input
    if not url:
        return {"error": "Please enter a website URL."}

    # 2. Check spaces
    if any(char.isspace() for char in url):
        return {"error": "URL cannot contain spaces."}

    # 3. Check unsupported URL scheme
    if "://" in url and not url.startswith(
        ("http://", "https://")
    ):
        return {
            "error": "Unsupported URL format. Use HTTP or HTTPS."
        }

    # 4. Add HTTPS if scheme is missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.hostname
        port = parsed.port
    except ValueError:
        return {"error": "Invalid URL or port number."}

    # 5. Check missing domain
    if not domain:
        return {"error": "Website domain is missing."}

    # 6. Prepare results
    results = {
        "url": url,
        "domain": domain,
        "https": parsed.scheme == "https",
        "valid_format": False,
        "is_ip_address": False,
        "suspicious_symbols": False,
        "unusual_port": False,
        "long_url": False,
        "many_subdomains": False,
        "punycode_domain": False,
        "warnings": []
    }

    # 7. Detect IP literals before applying domain-name rules.
    try:
        ipaddress.ip_address(domain)
        results["is_ip_address"] = True
        results["valid_format"] = True
        results["warnings"].append(
            "Website uses an IP address instead of a domain."
        )
    except ValueError:
        # 8. Check domain format
        try:
            domain_ascii = domain.encode("idna").decode("ascii")
            labels = domain_ascii.rstrip(".").split(".")

            if len(domain_ascii) > 253 or len(labels) < 2:
                raise ValueError()

            for label in labels:
                if not re.fullmatch(
                    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?",
                    label
                ):
                    raise ValueError()

            if len(labels[-1]) < 2:
                raise ValueError()

            results["valid_format"] = True

        except (UnicodeError, ValueError):
            return {"error": "Invalid website domain format."}

    # 9. Check suspicious symbols
    if "@" in parsed.netloc or "%" in url:
        results["suspicious_symbols"] = True
        results["warnings"].append(
            "URL contains potentially suspicious symbols."
        )

    # 10. Check unusual port
    if port is not None and port not in (80, 443):
        results["unusual_port"] = True
        results["warnings"].append(
            "Website uses a non-standard port."
        )

    # 11. Check URL length
    if len(url) > 100:
        results["long_url"] = True
        results["warnings"].append(
            "URL is unusually long."
        )

    # 12. Check subdomains
    if not results["is_ip_address"]:
        if len(domain_ascii.rstrip(".").split(".")) > 4:
            results["many_subdomains"] = True
            results["warnings"].append(
                "Website has many subdomains."
            )

    # 13. Check punycode
    if "xn--" in domain.lower():
        results["punycode_domain"] = True
        results["warnings"].append(
            "Domain contains internationalized encoding."
        )

    return results


# =====================================
# DISPLAY RESULTS
# =====================================

def display_results(results):

    print("\n" + "=" * 40)
    print("       SPHERESCAN URL ANALYSIS")
    print("=" * 40)

    # Handle invalid URL
    if "error" in results:
        print("\nINVALID URL!")
        print(results["error"])
        print("\nPlease check the address and try again.")
        print("=" * 40)
        return

    # Display URL information
    print("\nWebsite:", results["url"])
    print("Domain:", results["domain"])
    print("HTTPS:", "Yes" if results["https"] else "No")
    print(
        "Valid format:",
        "Yes" if results["valid_format"] else "No"
    )

    # Display security indicators
    print("\n--- SECURITY INDICATORS ---")

    indicators = [
        ("IP address", "is_ip_address"),
        ("Suspicious symbols", "suspicious_symbols"),
        ("Unusual port", "unusual_port"),
        ("Long URL", "long_url"),
        ("Many subdomains", "many_subdomains"),
        ("Punycode domain", "punycode_domain")
    ]

    for label, key in indicators:
        status = "Detected" if results[key] else "Not detected"
        print(label + ":", status)

    # Display warnings
    print("\n--- WARNINGS ---")

    if results["warnings"]:
        for warning in results["warnings"]:
            print("-", warning)
    else:
        print("No basic URL warnings detected.")

    print("\nNote: HTTPS does not guarantee website safety.")
    print("This is a basic URL analysis, not a full security scan.")

    print("=" * 40)


# =====================================
# MAIN PROGRAM
# =====================================

if __name__ == "__main__":

    website = input("\nEnter a website URL to scan: ")

    analysis = check_url(website)

    display_results(analysis)
