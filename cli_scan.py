import sys
from web_dns_lookup import dns_lookup, whois_lookup, security_analysis

if len(sys.argv) != 2:
    print("Usage: python cli_scan.py <domain>")
    sys.exit(1)

domain = sys.argv[1]

dns_data = dns_lookup(domain)
whois_data = whois_lookup(domain)
result = security_analysis(domain, dns_data, whois_data)

print("\n--- Domain Security Scan ---")
print(f"Domain: {domain}")
print(f"Risk Level: {result['risk']}")
print(f"Score: {result['score']}")
print("Alerts:")
for alert in result["alerts"]:
    print(f" - {alert}")
