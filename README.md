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

## 🚀 Features

- 🌐 DNS Records: A, AAAA, MX, NS, TXT, CNAME
- 🧠 Typosquatting detection against major brands
- ⏳ Domain age analysis
- 🚨 Risk scoring engine
- 🖥️ Web UI
- 🧪 REST API
- ⚙ CLI mode
- 🐳 Docker-ready

---

## 📦 Installation

```bash
git clone <repo-url>
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
