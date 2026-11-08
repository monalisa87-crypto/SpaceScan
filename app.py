import ipaddress
import json
import re
import socket
import sqlite3
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, HttpUrl

APP_TITLE = "Web Threat Detection API"
DB_PATH = "threat_intel.db"
TIMEOUT_SECONDS = 8
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 1_000_000
USER_AGENT = "WebThreatScanner/1.0 (defensive security research)"

app = FastAPI(title=APP_TITLE, version="1.0.0")


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048)


class ReportRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048)
    reason: str = Field(..., min_length=3, max_length=500)


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_key TEXT NOT NULL UNIQUE,
                reason TEXT NOT NULL,
                reports_count INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)


@app.on_event("startup")
def startup():
    init_db()


def canonicalize(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in ("http", "https"):
        raise HTTPException(400, "Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(400, "Invalid URL or embedded credentials are not allowed.")
    try:
        port = parsed.port
    except ValueError:
        raise HTTPException(400, "Invalid port.")
    if port and not (1 <= port <= 65535):
        raise HTTPException(400, "Invalid port.")
    host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    if not host or host == "localhost" or host.endswith(".localhost"):
        raise HTTPException(400, "Local hostnames are not allowed.")
    netloc = host
    if port:
        netloc += f":{port}"
    path = parsed.path or "/"
    return urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, ""))


def resolve_public_ips(host: str):
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise HTTPException(400, "The domain could not be resolved.")
    ips = sorted({item[4][0] for item in records})
    if not ips:
        raise HTTPException(400, "The domain has no IP addresses.")
    for value in ips:
        ip = ipaddress.ip_address(value)
        # Blocks loopback, private, link-local, multicast, reserved and unspecified IPs.
        if not ip.is_global:
            raise HTTPException(400, f"Blocked non-public destination address: {value}")
    return ips


def certificate_check(host: str, port: int, ips: list[str]):
    result = {"checked": False, "valid": False, "subject": None,
              "issuer": None, "not_after": None, "tls_version": None, "error": None}
    if port != 443:
        result["error"] = "Certificate check is only performed on HTTPS port 443."
        return result
    context = ssl.create_default_context()
    last_error = None
    for ip in ips:
        try:
            # Connect to the already validated public IP, while verifying the hostname.
            raw_sock = socket.create_connection((ip, port), timeout=TIMEOUT_SECONDS)
            with context.wrap_socket(raw_sock, server_hostname=host) as sock:
                cert = sock.getpeercert()
                result.update({
                    "checked": True,
                    "valid": True,
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "not_after": cert.get("notAfter"),
                    "tls_version": sock.version(),
                    "error": None
                })
                return result
        except Exception as exc:
            last_error = str(exc)
    result["checked"] = True
    result["error"] = last_error or "TLS connection failed."
    return result


def fetch_safely(url: str):
    """Fetch one URL at a time; validate DNS and every redirect destination."""
    current = url
    chain = []
    for _ in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        ips = resolve_public_ips(host)

        # Requests follows no redirects. DNS is checked immediately before each request.
        # For production, also enforce outbound-network/IP allow rules at the infrastructure layer.
        try:
            response = requests.get(
                current,
                headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
                timeout=TIMEOUT_SECONDS,
                allow_redirects=False,
                stream=True,
                verify=True
            )
        except requests.RequestException as exc:
            raise HTTPException(502, f"Could not retrieve website: {str(exc)[:180]}")

        location = response.headers.get("Location")
        chain.append({"url": current, "status_code": response.status_code})
        if response.is_redirect or response.is_permanent_redirect:
            response.close()
            if not location:
                break
            current = canonicalize(urljoin(current, location))
            continue

        body = bytearray()
        try:
            for chunk in response.iter_content(chunk_size=16384):
                if not chunk:
                    continue
                body.extend(chunk)
                if len(body) > MAX_BODY_BYTES:
                    break
            headers = dict(response.headers)
            status = response.status_code
            final_url = response.url
        finally:
            response.close()
        return {
            "final_url": final_url,
            "status_code": status,
            "headers": headers,
            "body": bytes(body[:MAX_BODY_BYTES]),
            "truncated": len(body) > MAX_BODY_BYTES,
            "redirect_chain": chain,
            "host": host,
            "port": port,
            "ips": ips
        }
    raise HTTPException(400, "Too many redirects.")


def analyze_html(body: bytes, headers: dict, final_url: str):
    content_type = headers.get("Content-Type", "")
    if "html" not in content_type.lower():
        return {"title": None, "password_forms": 0, "external_links": 0,
                "hidden_iframes": 0, "html_analyzed": False}

    text = body.decode("utf-8", errors="replace")
    soup = BeautifulSoup(text, "html.parser")
    title = soup.title.get_text(" ", strip=True)[:200] if soup.title else None
    password_forms = 0
    for form in soup.find_all("form"):
        if form.find("input", attrs={"type": re.compile("^password$", re.I)}):
            password_forms += 1
    host = urlparse(final_url).hostname
    external_links = 0
    for link in soup.find_all("a", href=True):
        target = urlparse(urljoin(final_url, link["href"]))
        if target.hostname and target.hostname != host:
            external_links += 1
    hidden_iframes = sum(
        1 for frame in soup.find_all("iframe")
        if frame.get("hidden") is not None or frame.get("style", "").replace(" ", "").lower().find("display:none") >= 0
    )
    return {"title": title, "password_forms": password_forms,
            "external_links": external_links, "hidden_iframes": hidden_iframes,
            "html_analyzed": True}


def threat_intel_lookup(url: str):
    # Community reports are signals, not proof. The URL is stored without query parameters.
    parsed = urlparse(url)
    key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".lower()
    with db() as con:
        row = con.execute("SELECT reports_count, reason FROM reports WHERE url_key=?", (key,)).fetchone()
    return {"community_report_count": row["reports_count"] if row else 0,
            "community_reported": bool(row),
            "community_reason": row["reason"] if row else None}


def score_findings(url, fetched, cert, html, intel):
    score = 0
    findings = []
    parsed = urlparse(url)

    def add(points, code, detail):
        nonlocal score
        score += points
        findings.append({"code": code, "severity": "high" if points >= 25 else
                         "medium" if points >= 10 else "low", "detail": detail})

    if parsed.scheme != "https":
        add(25, "NO_HTTPS", "The submitted URL does not use HTTPS.")
    if fetched["status_code"] >= 400:
        add(10, "HTTP_ERROR", f"Website returned HTTP {fetched['status_code']}.")
    if parsed.hostname and re.search(r"(login|verify|secure|account|update|banking|wallet)", parsed.hostname, re.I):
        add(8, "SUSPICIOUS_HOST_KEYWORDS", "The hostname contains words commonly used in deceptive URLs.")
    if "xn--" in (parsed.hostname or ""):
        add(15, "PUNYCODE_HOST", "The hostname uses internationalized/punycode encoding; inspect for lookalike characters.")
    if len(url) > 180:
        add(5, "LONG_URL", "The URL is unusually long.")
    if parsed.hostname and parsed.hostname.count("-") >= 3:
        add(5, "MANY_HYPHENS", "The hostname contains several hyphens.")
    if cert.get("checked") and not cert.get("valid"):
        add(25, "TLS_CERTIFICATE_INVALID", "TLS certificate validation failed.")
    if parsed.scheme == "https" and cert.get("valid") and cert.get("tls_version") in ("TLSv1", "TLSv1.1"):
        add(15, "OLD_TLS_VERSION", "The server negotiated an obsolete TLS version.")
    if html["password_forms"] and parsed.scheme != "https":
        add(30, "PASSWORD_FORM_OVER_HTTP", "A password form is served over unencrypted HTTP.")
    if html["hidden_iframes"]:
        add(10, "HIDDEN_IFRAME", "The page contains hidden iframe elements.")
    if intel["community_reported"]:
        add(min(40, 20 + 5 * max(0, intel["community_report_count"] - 1)),
            "COMMUNITY_REPORTS", f"Community users reported this URL {intel['community_report_count']} time(s).")

    score = min(100, score)
    label = "high" if score >= 60 else "medium" if score >= 25 else "low"
    return {"risk_score": score, "risk_level": label, "findings": findings}


@app.get("/health")
def health():
    return {"status": "ok", "service": APP_TITLE}


@app.post("/scan")
def scan(request: ScanRequest):
    url = canonicalize(request.url)
    parsed = urlparse(url)
    # Validate all DNS answers before making a network request.
    ips = resolve_public_ips(parsed.hostname)
    fetched = fetch_safely(url)

    cert = {"checked": False, "valid": False, "error": "Not HTTPS"}
    if parsed.scheme == "https":
        cert = certificate_check(fetched["host"], fetched["port"], fetched["ips"])

    html = analyze_html(fetched["body"], fetched["headers"], fetched["final_url"])
    intel = threat_intel_lookup(fetched["final_url"])
    assessment = score_findings(url, fetched, cert, html, intel)

    return {
        "scanned_url": url,
        "final_url": fetched["final_url"],
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "resolved_ips": ips,
        "http": {"status_code": fetched["status_code"],
                 "server": fetched["headers"].get("Server"),
                 "content_type": fetched["headers"].get("Content-Type"),
                 "redirect_chain": fetched["redirect_chain"],
                 "body_truncated": fetched["truncated"]},
        "tls_certificate": cert,
        "security_headers": {
            name: fetched["headers"].get(name) for name in [
                "Strict-Transport-Security", "Content-Security-Policy",
                "X-Content-Type-Options", "X-Frame-Options",
                "Referrer-Policy", "Permissions-Policy"
            ]
        },
        "page_analysis": html,
        "threat_intelligence": intel,
        **assessment,
        "disclaimer": "Heuristic result only; a low score does not guarantee a website is safe."
    }


@app.post("/report")
def report(request: ReportRequest):
    url = canonicalize(request.url)
    parsed = urlparse(url)
    key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".lower()
    with db() as con:
        con.execute("""
            INSERT INTO reports(url_key, reason, reports_count, created_at)
            VALUES(?, ?, 1, ?)
            ON CONFLICT(url_key) DO UPDATE SET
                reports_count = reports_count + 1,
                reason = excluded.reason
        """, (key, request.reason.strip(),
              datetime.now(timezone.utc).isoformat()))
    return {"message": "Report received", "reported_url": key}