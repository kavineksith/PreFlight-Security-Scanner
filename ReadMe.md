# 🛡️ PreFlight Security Scanner v2.0 (Enterprise Overhaul)

PreFlight Security Scanner is a powerful, automated Dynamic Application Security Testing (DAST) suite engineered for modern enterprise environments. Version 2.0 transforms the original educational script into a **multi-threaded**, highly modular vulnerability scanner capable of testing across 22 distinct attack vectors while inherently mapping findings to real-world threat intelligence.

## ✨ Enterprise Features

* **Multi-Threaded Architecture**: Massively accelerated execution using `ThreadPoolExecutor`—concurrently runs OWASP and API tests without locking the main execution pipeline.
* **Dynamic Intelligence Feeds**: Integrated `PayloadUpdater` automatically fetches over **150,000+ advanced payloads** (from SecLists and PayloadAllTheThings) on demand, enabling comprehensive brute-forcing of DNS subdomains, JWT secrets, XSS, and SQLi endpoints.
* **Multi-Year OWASP Taxonomy**: 
  * Findings explicitly map to strict compliance frameworks: **OWASP Web Top 10 (2017, 2021, 2025)** and **API Top 10 (2019, 2023, 2025)**.
* **Intelligence Mappings**: Auto-aligns discovered vulnerabilities with the **MITRE ATT&CK Matrix** (Tactics & Techniques), associated CVE patterns, CWE IDs, and assigns CVSS v3.1 / EPSS severity scoring.
* **Granular CI/CD Ready**: 
  * Fully configurable scan profiles (`--mode full`, `--mode quick`, `--mode recon`).
  * Return-code blocking for critical vulnerabilities allows perfect integration with GitHub Actions (see `.github/workflows/`).
* **Cloud Compatible**: Verified execution support within Google Colab environments.

## 🧩 22 Advanced Scan Modules

The scanning engine comprises highly targeted, robust python modules checking critical security flaws:
1. **DNS Recon**: Subdomain enumeration (110k+ vectors), Zone transfer checks, Subdomain Takeover/CNAME validation.
2. **Injection Tester**: Error/Boolean/Time-based SQLi, NoSQLi, OS Command Injection, LDAP, SSTI, CRLF.
3. **Session & Auth**: MFA Bybass, Session Fixation, Broken Object Level Auth (BOLA).
4. **JWT Analyzer**: Forged 'none' algorithms, weak signing keys (via massive dictionaries), JKU/Kid header manipulation.
5. **Business Logic**: Privilege Escalation, API Rate Limiting Bypass, IDOR tests.
6. **Config & Crypto**: CORS Audits, SSRF Metadata scraping, Cryptographic strengths.

## 🚀 Quick Start

Ensure you have Python 3.9+ and install dependencies:

```bash
pip install -r requirements.txt
```

### Basic Full Scan
```bash
python preflight.py https://staging.example.com --mode full
```

### 🧠 Massive Database Initialization (Enterprise Scan)
Trigger the internal downloader to pull large payload dictionaries before running tests:
```bash
python preflight.py https://staging.example.com --update-payloads --mode full
```

### CI/CD / GitHub Action Blocking
Set the scanner to fail the build if any "CRITICAL" issues are identified:
```bash
python preflight.py https://staging.example.com --severity-threshold CRITICAL
```

## 📊 Comprehensive Reporting

Results are aggregated into the `/scan_reports` directory post-scan and available in:
* **HTML**: Executive summaries with color-coded severity visuals.
* **CSV**: Developer-friendly spreadsheets mapping CWE, REMEDIATION, and TIER tags.
* **JSON**: Raw structured data easily digested by platforms like Jira or DefectDojo.

## 🧪 Testing the Scanner 

The suite guarantees 90%+ code coverage for framework reliability:
```bash
pytest tests/ -v --cov=modules
```

## 📜 License
Distributed under the MIT License. See `LICENSE` for more information.