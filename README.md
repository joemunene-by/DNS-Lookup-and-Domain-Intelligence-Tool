# 🔐 Web DNS Security Scanner

A hybrid **Web + CLI cybersecurity reconnaissance tool** that performs:

- DNS record inspection
- WHOIS intelligence
- Typosquatting detection
- IP reputation heuristics
- Risk scoring (LOW / MEDIUM / HIGH)
- JSON API access

Built for **security research, phishing detection, and SOC analysis**.

---

🔐 Core Features
🌐 DNS Intelligence

A, AAAA (IPv6), MX, NS, TXT, CNAME record enumeration

Detects missing or misconfigured DNS records

Highlights email infrastructure risks

🧾 WHOIS Analysis

Registrar identification

Domain creation date extraction

Country attribution

Detection of newly registered domains (common in phishing attacks)

⚠️ Security Risk Analysis

🚨 Newly registered domain detection

🚨 Missing MX record warnings

🚨 Domain reputation red flags

🧠 Typosquatting Detection (Advanced)

Detects domains attempting to impersonate well-known brands such as:

Google

Facebook

Instagram

PayPal

Microsoft

Example:

paypa1-login[.]com → FLAGGED


This is a real phishing detection technique used in production security tools.

🖥️ Interfaces
🧪 CLI Tool

Fast terminal-based domain scanning

Ideal for automation and scripting

Clean, structured output

🌍 Web Application (Flask)

User-friendly web dashboard

Displays DNS records, WHOIS data, and alerts

Designed for analyst-style investigation

🛠️ Tech Stack
Technology                    Purpose

-Python	                      -Core logic
-dnspython                   	-DNS resolution
-python-whois	                -WHOIS intelligence
-Flask	                        -Web interface
-HTML / Jinja2	                -Frontend templating
-Git                         	-Version control
🚀 Why This Project Matters 

This is not a basic DNS lookup script.

This project demonstrates:

✅ Practical cybersecurity knowledge

✅ Understanding of attacker & defender perspectives

✅ Secure Python development

✅ Real-world domain risk analysis logic

✅ Ability to turn raw data into actionable security insights

It reflects the same workflow used by security analysts when investigating phishing domains, suspicious URLs, or newly registered infrastructure.

📂 Project Structure
DNS-Lookup-and-Domain-Intelligence-Tool/
│
├── web_dns_lookup.py      # Flask web app
├── cli_dns_lookup.py      # CLI scanner
├── templates/
│   └── index.html
├── requirements.txt
├── README.md
└── .gitignore


---

## 📦 Installation

```bash
git clone https://github.com/joemunene-by/DNS-Lookup-and-Domain-Intelligence-Tool
cd project
pip install -r requirements.txt
▶ Run Web App
bash
python web_dns_lookup.py
Visit: http://localhost:5000

🧪 Run CLI Mode
bash
python cli_scan.py example.com
🔌 API Usage
http
GET /api/scan?domain=example.com
Returns full JSON intelligence.

🐳 Docker Run
bash
docker build -t dns-scanner .
docker run -p 5000:5000 dns-scanner
⚠ Legal Notice
This tool is for educational and defensive security research only.
Do NOT scan domains you do not own or have permission to analyze.

🧠 Future Improvements
Live AbuseIPDB integration

SSL certificate analysis

ASN & hosting provider detection

Threat feed correlation

👨‍💻 Author
Joe Munene
Built by a cybersecurity learner focused on ethical hacking & defense.


