
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone


# ==========================================
# SPHERESCAN - CERTIFICATE VALIDATOR
# ==========================================

def check_certificate(url):

    url = url.strip()

    # 1. Check empty input
    if not url:
        return {"error": "Please enter a website URL."}

    # 2. Add HTTPS if scheme is missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

    except ValueError:
        return {"error": "Invalid website URL or port."}

    if parsed.scheme not in ("http", "https") or not hostname:
        return {"error": "Invalid website URL."}

    if parsed.scheme != "https":
        return {"hostname": hostname, "error": "Certificate checks require an HTTPS URL."}

    port = parsed.port or 443

    # 3. Prepare SSL context
    context = ssl.create_default_context()

    try:
        # 4. Connect securely to website
        with socket.create_connection(
            (hostname, port), timeout=8
        ) as connection:

            with context.wrap_socket(
                connection, server_hostname=hostname
            ) as secure_connection:

                # 5. Get certificate information
                certificate = secure_connection.getpeercert()

                issuer = certificate.get("issuer", ())
                subject = certificate.get("subject", ())

                issuer_name = "Unknown"
                subject_name = "Unknown"

                for group in issuer:
                    for key, value in group:
                        if key == "organizationName":
                            issuer_name = value

                for group in subject:
                    for key, value in group:
                        if key == "commonName":
                            subject_name = value

                # 6. Get certificate validity dates
                not_before = certificate.get("notBefore")
                not_after = certificate.get("notAfter")

                valid_from = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(not_before),
                    timezone.utc
                )

                valid_until = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(not_after),
                    timezone.utc
                )

                current_time = datetime.now(timezone.utc)

                # 7. Check expiration
                expired = current_time > valid_until

                return {
                    "hostname": hostname,
                    "certificate_found": True,
                    "trusted": True,
                    "domain": subject_name,
                    "issuer": issuer_name,
                    "valid_from": valid_from.strftime(
                        "%d %B %Y"
                    ),
                    "valid_until": valid_until.strftime(
                        "%d %B %Y"
                    ),
                    "expired": expired,
                    "days_remaining": (
                        valid_until - current_time
                    ).days,
                    "tls_version": secure_connection.version()
                }

    except ssl.SSLCertVerificationError as error:
        return {
            "hostname": hostname,
            "certificate_found": True,
            "trusted": False,
            "error": "Certificate verification failed: " + str(error)
        }

    except socket.timeout:
        return {
            "hostname": hostname,
            "error": "Connection timed out. Try again later."
        }

    except socket.gaierror:
        return {
            "hostname": hostname,
            "error": "Website domain could not be found."
        }

    except ConnectionRefusedError:
        return {
            "hostname": hostname,
            "error": "Website refused the connection."
        }

    except OSError as error:
        return {
            "hostname": hostname,
            "error": "Connection error: " + str(error)
        }


# ==========================================
# DISPLAY CERTIFICATE REPORT
# ==========================================

def display_certificate_report(result):

    print("\n" + "=" * 45)
    print("      SPHERESCAN CERTIFICATE REPORT")
    print("=" * 45)

    # Handle errors
    if "error" in result:

        print("\nCERTIFICATE CHECK FAILED!")
        print(result["error"])

        if result.get("certificate_found"):
            print("\nCertificate was found but could not be trusted.")

        print("=" * 45)
        return

    print("\nWebsite:", result["hostname"])

    print(
        "Certificate Found:",
        "Yes" if result["certificate_found"] else "No"
    )

    print(
        "Trusted:",
        "Yes" if result["trusted"] else "No"
    )

    print("Certificate Domain:", result["domain"])
    print("Certificate Issuer:", result["issuer"])

    print("\n--- VALIDITY INFORMATION ---")

    print("Valid From:", result["valid_from"])
    print("Valid Until:", result["valid_until"])

    print(
        "Expired:",
        "Yes" if result["expired"] else "No"
    )

    if not result["expired"]:
        print("Days Remaining:", result["days_remaining"])

    print("\nTLS Version:", result["tls_version"])

    print("\n--- FINAL RESULT ---")

    if result["expired"]:
        print("WARNING: Certificate has expired.")

    else:
        print("Certificate verification successful.")

    print("\nIMPORTANT:")
    print("A valid certificate does not guarantee")
    print("that a website is free from phishing.")

    print("=" * 45)


# ==========================================
# MAIN PROGRAM
# ==========================================

if __name__ == "__main__":

    website = input(
        "\nEnter a website URL to check its certificate: "
    )

    result = check_certificate(website)

    display_certificate_report(result)
