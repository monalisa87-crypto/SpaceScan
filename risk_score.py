
# ==========================================
# SPHERESCAN - RISK SCORE CHECKER
# ==========================================

def calculate_risk(results):

    # Check whether URL analysis failed
    if "error" in results:
        return {
            "score": None,
            "level": "INVALID",
            "message": results["error"],
            "warnings": []
        }

    score = 0
    warnings = []

    # 1. Check HTTPS
    if not results.get("https", False):
        score += 15
        warnings.append("Website does not use HTTPS")

    # 2. Check IP address
    if results.get("is_ip_address", False):
        score += 25
        warnings.append("Website uses an IP address")

    # 3. Check suspicious symbols
    if results.get("suspicious_symbols", False):
        score += 15
        warnings.append("Suspicious URL symbols detected")

    # 4. Check unusual port
    if results.get("unusual_port", False):
        score += 10
        warnings.append("Unusual port detected")

    # 5. Check URL length
    if results.get("long_url", False):
        score += 10
        warnings.append("Unusually long URL")

    # 6. Check many subdomains
    if results.get("many_subdomains", False):
        score += 10
        warnings.append("Too many subdomains")

    # 7. Check punycode
    if results.get("punycode_domain", False):
        score += 15
        warnings.append("Internationalized domain encoding detected")

    # Limit score to 100
    score = min(score, 100)

    # Determine risk level
    if score <= 20:
        level = "LOW"
        message = "Few suspicious indicators detected."

    elif score <= 50:
        level = "MEDIUM"
        message = "Some suspicious indicators detected."

    else:
        level = "HIGH"
        message = "Multiple suspicious indicators detected."

    return {
        "score": score,
        "level": level,
        "message": message,
        "warnings": warnings
    }


# ==========================================
# DISPLAY RISK REPORT
# ==========================================

def display_risk_report(report):

    print("\n" + "=" * 40)
    print("       SPHERESCAN RISK REPORT")
    print("=" * 40)

    if report["level"] == "INVALID":
        print("\nINVALID URL")
        print(report["message"])
        print("=" * 40)
        return

    print("\nRisk Score:", str(report["score"]) + "/100")
    print("Risk Level:", report["level"])

    print("\nAssessment:")
    print(report["message"])

    print("\n--- DETECTED WARNINGS ---")

    if report["warnings"]:
        for warning in report["warnings"]:
            print("-", warning)
    else:
        print("No basic suspicious indicators detected.")

    print("\nIMPORTANT:")
    print("This score is a heuristic estimate,")
    print("not proof that a website is safe or malicious.")

    print("=" * 40)


# ==========================================
# TESTING
# ==========================================

if __name__ == "__main__":

    test_results = {
        "https": False,
        "is_ip_address": True,
        "suspicious_symbols": True,
        "unusual_port": False,
        "long_url": True,
        "many_subdomains": False,
        "punycode_domain": False
    }

    report = calculate_risk(test_results)

    display_risk_report(report)
