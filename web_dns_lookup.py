"""
DNS Lookup and Domain Intelligence Tool
A cybersecurity utility for DNS reconnaissance, WHOIS lookups,
security header analysis, and reverse DNS resolution.
"""

import re
import socket
from datetime import datetime, timezone

import dns.resolver
import dns.reversename
import requests
import whois
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
)

POPULAR_BRANDS = [
    "google", "facebook", "amazon", "apple", "microsoft", "netflix",
    "paypal", "twitter", "instagram", "linkedin", "github", "yahoo",
    "spotify", "uber", "dropbox", "slack", "zoom", "adobe", "oracle",
    "salesforce",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]


def _validate_domain(domain: str) -> str | None:
    """Return cleaned domain or None if invalid."""
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = domain.split("//", 1)[1].split("/", 0)[0]
    domain = domain.rstrip(".")
    if DOMAIN_RE.match(domain):
        return domain
    return None


def _serialize_datetime(obj):
    """Convert datetime or list of datetimes to ISO strings."""
    if obj is None:
        return None
    if isinstance(obj, list):
        return [_serialize_datetime(item) for item in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def _check_typosquatting(domain: str) -> list[dict]:
    """Check if domain looks like a typosquat of a popular brand."""
    alerts = []
    label = domain.split(".")[0]
    for brand in POPULAR_BRANDS:
        if brand == label:
            continue
        # Simple Levenshtein-like heuristic: one character difference
        if abs(len(brand) - len(label)) <= 1 and brand != label:
            common = sum(a == b for a, b in zip(brand, label))
            if common >= max(len(brand), len(label)) - 1:
                alerts.append({
                    "type": "typosquatting",
                    "message": f"Domain '{label}' is suspiciously similar to '{brand}'"
                })
    return alerts


def _check_domain_age(creation_date) -> list[dict]:
    """Flag domains younger than 30 days."""
    alerts = []
    if creation_date is None:
        return alerts
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if isinstance(creation_date, datetime):
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation_date).days
        if age_days < 30:
            alerts.append({
                "type": "new_domain",
                "message": f"Domain registered only {age_days} day(s) ago — potentially suspicious"
            })
    return alerts


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/dns", methods=["GET"])
def dns_lookup():
    """Resolve multiple DNS record types for a domain."""
    domain = _validate_domain(request.args.get("domain", ""))
    if not domain:
        return jsonify({"error": "Invalid domain name"}), 400

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    results: dict[str, list[str]] = {}
    alerts: list[dict] = []

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                if rtype == "MX":
                    records.append(f"{rdata.preference} {rdata.exchange}")
                elif rtype == "SOA":
                    records.append(
                        f"{rdata.mname} {rdata.rname} "
                        f"serial={rdata.serial} refresh={rdata.refresh} "
                        f"retry={rdata.retry} expire={rdata.expire} "
                        f"minimum={rdata.minimum}"
                    )
                else:
                    records.append(rdata.to_text())
            results[rtype] = records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            results[rtype] = []

    # Security alert: no MX records may indicate email spoofing risk
    if not results.get("MX"):
        alerts.append({
            "type": "no_mx",
            "message": "No MX records found — domain may be vulnerable to email spoofing"
        })

    alerts.extend(_check_typosquatting(domain))

    return jsonify({"domain": domain, "records": results, "alerts": alerts})


@app.route("/api/whois", methods=["GET"])
def whois_lookup():
    """Return WHOIS registration data for a domain."""
    domain = _validate_domain(request.args.get("domain", ""))
    if not domain:
        return jsonify({"error": "Invalid domain name"}), 400

    try:
        w = whois.whois(domain)
    except Exception as exc:
        return jsonify({"error": f"WHOIS lookup failed: {exc}"}), 502

    creation_date = w.creation_date
    alerts = _check_domain_age(creation_date)

    data = {
        "domain_name": w.domain_name if isinstance(w.domain_name, str)
        else (w.domain_name[0] if w.domain_name else None),
        "registrar": w.registrar,
        "creation_date": _serialize_datetime(w.creation_date),
        "expiration_date": _serialize_datetime(w.expiration_date),
        "updated_date": _serialize_datetime(w.updated_date),
        "name_servers": list(w.name_servers) if w.name_servers else [],
        "status": w.status if isinstance(w.status, list)
        else ([w.status] if w.status else []),
        "emails": w.emails if isinstance(w.emails, list)
        else ([w.emails] if w.emails else []),
        "country": w.country,
        "org": w.org,
    }

    return jsonify({"domain": domain, "whois": data, "alerts": alerts})


@app.route("/api/security", methods=["GET"])
def security_headers():
    """Fetch a domain over HTTPS and inspect security-related response headers."""
    domain = _validate_domain(request.args.get("domain", ""))
    if not domain:
        return jsonify({"error": "Invalid domain name"}), 400

    url = f"https://{domain}"
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "DNS-Intel-Tool/1.0"})
    except requests.RequestException as exc:
        return jsonify({"error": f"Could not reach {url}: {exc}"}), 502

    found: dict[str, str] = {}
    missing: list[str] = []
    for header in SECURITY_HEADERS:
        value = resp.headers.get(header)
        if value:
            found[header] = value
        else:
            missing.append(header)

    score = int(len(found) / len(SECURITY_HEADERS) * 100)

    return jsonify({
        "domain": domain,
        "url_checked": resp.url,
        "status_code": resp.status_code,
        "headers_present": found,
        "headers_missing": missing,
        "score": score,
        "server": resp.headers.get("Server", "Unknown"),
    })


@app.route("/api/reverse", methods=["GET"])
def reverse_dns():
    """Resolve IP addresses for a domain, then perform reverse lookups."""
    domain = _validate_domain(request.args.get("domain", ""))
    if not domain:
        return jsonify({"error": "Invalid domain name"}), 400

    results: list[dict] = []

    # Gather A and AAAA records
    ips: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(domain, rtype)
            ips.extend(rdata.to_text() for rdata in answers)
        except Exception:
            pass

    for ip in ips:
        entry: dict = {"ip": ip, "ptr": None}
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev_name, "PTR")
            entry["ptr"] = [rdata.to_text() for rdata in answers]
        except Exception:
            entry["ptr"] = []
        results.append(entry)

    return jsonify({"domain": domain, "reverse": results})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
