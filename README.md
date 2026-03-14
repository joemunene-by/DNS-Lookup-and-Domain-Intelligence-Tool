# DNS Lookup and Domain Intelligence Tool

[![GitHub Actions](https://github.com/joemunene-by/DNS-Lookup-and-Domain-Intelligence-Tool/actions/workflows/python-tests.yml/badge.svg)](https://github.com/joemunene-by/DNS-Lookup-and-Domain-Intelligence-Tool/actions/workflows/python-tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

---

## Project Overview

This **DNS Lookup and Domain Intelligence Tool** is a comprehensive cybersecurity utility designed to assist security professionals, researchers, and enthusiasts in gathering critical domain data and detecting potential threats.

With this tool, you can:

- Perform detailed DNS lookups including A, AAAA, MX, NS, TXT, and CNAME records.
- Retrieve WHOIS information for domains including registrar, creation date, and country.
- Detect security issues such as missing MX records (potential email misuse risk).
- Identify possible typosquatting attacks by comparing domains to popular brand names.
- Analyze domain age to flag newly registered domains that may be suspicious.

The tool is built as a **user-friendly web application** powered by Python and Flask, with a simple interface for quick domain investigations.

---

## Key Features

- **Multi-record DNS queries** for in-depth domain analysis.
- **WHOIS integration** to provide domain ownership and registration details.
- **Security alerts** for common red flags including typosquatting and domain age.
- **Easy-to-use web UI** for fast lookups without command-line complexity.
- **CI pipeline** with GitHub Actions ensures code quality and automated testing.

---

## Getting Started

### Prerequisites

- Python 3.10 or higher
- pip package manager

### Installation

```bash
git clone https://github.com/joemunene-by/DNS-Lookup-and-Domain-Intelligence-Tool.git
cd DNS-Lookup-and-Domain-Intelligence-Tool
pip install -r requirements.txt
Running the Web Application
bash
Copy code
python web_dns_lookup.py
Open your browser and navigate to http://127.0.0.1:5000 to use the tool.

Project Structure
web_dns_lookup.py — Main Flask app serving the web UI and backend logic.

templates/index.html — HTML template for the web interface.

.github/workflows/python-tests.yml — GitHub Actions CI pipeline config.

README.md — Project documentation.

requirements.txt — Python dependencies.

Future Enhancements
Expand typosquatting detection with fuzzy matching algorithms.

Add more WHOIS fields and DNS record types.

Integrate API support for automated domain intelligence workflows.

Deploy as a public web service with authentication.

License
This project is licensed under the MIT License.

Contact
Created by Joe Munene — passionate about cybersecurity and building practical tools.

Feel free to open issues or submit pull requests!

Thank you for checking out this project!
