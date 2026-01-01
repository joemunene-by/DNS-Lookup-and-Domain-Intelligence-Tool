from flask import Flask, render_template, request, jsonify
import dns.resolver
import whois
import socket
from datetime import datetime

app = Flask(__name__)

# -----------------------------------
# Typosquatting Detection
# -----------------------------------
def is_typosquat(domain, brands=None):
    if not brands:
        brands = ["google", "facebook", "instagram", "paypal", "microsoft"]

    domain = domain.lower()
    for brand in brands:
        if brand in domain and domain != f"{brand}.com":
            return True, brand
    return False, None


# -----------------------------------
# DNS Lookup
# -----------------------------------
def dns_lookup(domain):
    records = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    results = {}

    for record in records:
        try:
            answers = dns.resolver.resolve(domain, record)
            results[record] = [str(r) for r in answers]
        except Exception:
            results[record] = []

    return results


# -----------------------------------
# WHOIS Lookup
# -----------------------------------
def whois_lookup(domain):
    try:
        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date and creation_date.tzinfo:
            creation_date = creation_date.replace(tzinfo=None)

        return {
            "Registrar": w.registrar,
            "Creation Date": creation_date,
            "Country": w.country
        }
    except Exception:
        return None


# -----------------------------------
# IP Reputation (Offline Heuristic)
# -----------------------------------
def ip_reputation_check(domain):
    try:
        ip = socket.gethostbyname(domain)

        bad_ranges = ["185.", "45.", "193.", "91."]
        for prefix in bad_ranges:
            if ip.startswith(prefix):
                return "Suspicious IP range"

        return "No known abuse detected"
    except Exception:
        return "IP lookup failed"


# -----------------------------------
# Risk Scoring Engine
# -----------------------------------
def security_analysis(domain, dns_data, whois_data):
    alerts = []
    score = 0

    if not dns_data.get("MX"):
        alerts.append("No MX records found")
        score += 20

    if whois_data and whois_data.get("Creation Date"):
        age_days = (datetime.now() - whois_data["Creation Date"]).days
        if age_days < 30:
            alerts.append(f"New domain ({age_days} days old)")
            score += 30

    typo, brand = is_typosquat(domain)
    if typo:
        alerts.append(f"Possible typosquatting of '{brand}'")
        score += 40

    ip_rep = ip_reputation_check(domain)
    if "Suspicious" in ip_rep:
        alerts.append(ip_rep)
        score += 20

    if score >= 70:
        risk = "HIGH"
    elif score >= 40:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "risk": risk,
        "score": score,
        "alerts": alerts
    }


# -----------------------------------
# Web UI
# -----------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        domain = request.form["domain"].strip()
        dns_data = dns_lookup(domain)
        whois_data = whois_lookup(domain)
        result = security_analysis(domain, dns_data, whois_data)

    return render_template("index.html", result=result)


# -----------------------------------
# JSON API
# -----------------------------------
@app.route("/api/scan", methods=["GET"])
def api_scan():
    domain = request.args.get("domain")
    if not domain:
        return jsonify({"error": "Domain parameter required"}), 400

    dns_data = dns_lookup(domain)
    whois_data = whois_lookup(domain)
    result = security_analysis(domain, dns_data, whois_data)

    return jsonify({
        "domain": domain,
        "dns": dns_data,
        "whois": whois_data,
        "analysis": result
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
