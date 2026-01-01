import dns.resolver
import whois
from datetime import datetime

def is_typosquat(domain, brands=None):
    if not brands:
        brands = ["instagram", "facebook", "google", "paypal", "microsoft"]

    domain = domain.lower()

    for brand in brands:
        if brand in domain and domain != f"{brand}.com":
            return True, brand

    return False, None


# ---------------- DNS LOOKUP ----------------
def dns_lookup(domain):
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    results = {}

    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            results[record] = [str(rdata) for rdata in answers]
        except Exception:
            results[record] = []

    return results


# ---------------- WHOIS LOOKUP ----------------
def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return {
            "Registrar": w.registrar,
            "Creation Date": w.creation_date,
            "Expiration Date": w.expiration_date,
            "Country": w.country
        }
    except Exception:
        return None


# ---------------- SECURITY ANALYSIS ----------------
def security_analysis(dns_data, whois_data):
    alerts = []

    if not dns_data.get("MX"):
        alerts.append("No MX records found (email misconfiguration or phishing domain)")

    txt_records = dns_data.get("TXT", [])
    if not any("spf" in r.lower() for r in txt_records):
        alerts.append("SPF record missing (email spoofing risk)")

    if whois_data and whois_data.get("Creation Date"):
        creation_date = whois_data["Creation Date"]
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        domain_age = (datetime.now() - creation_date).days
        if domain_age < 30:
            alerts.append("Domain is newly registered (high phishing risk)")

    return alerts


# ---------------- MAIN ----------------
def main():
    domain = input("Enter domain name: ").strip()

    print("\n[+] Performing DNS lookup...")
    dns_data = dns_lookup(domain)

    print("\n[+] Performing WHOIS lookup...")
    whois_data = whois_lookup(domain)

    print("\n===== DNS RECORDS =====")
    for record, values in dns_data.items():
        print(f"\n{record}:")
        if values:
            for v in values:
                print("  ", v)
        else:
            print("   None")

    print("\n===== WHOIS INFO =====")
    if whois_data:
        for k, v in whois_data.items():
            print(f"{k}: {v}")
    else:
        print("WHOIS data unavailable")

    print("\n===== SECURITY ANALYSIS =====")
    alerts = security_analysis(dns_data, whois_data)
    if alerts:
        for alert in alerts:
            print("[!]", alert)
    else:
        print("No obvious security risks detected")


if __name__ == "__main__":
    main()
