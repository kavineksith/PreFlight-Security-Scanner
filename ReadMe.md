# 🔒 PreFlight Security Scanner

**Pre-Production Security Validation Tool for Educational Home Lab Use**

## ⚠️ DISCLAIMER
This tool is for **AUTHORIZED TESTING ONLY** in home lab or staging environments you own. Never scan domains without explicit permission. Unauthorized testing may violate laws.

## Features
- ✅ OWASP Top 10 (2023) vulnerability scanning
- ✅ OWASP API Top 10 (2023) security testing
- ✅ Authentication & Authorization tests (IDOR, privilege escalation)
- ✅ CVSS v3.1 scoring for all findings
- ✅ Pre-production hardening checks
- ✅ HTML/JSON/CSV reports with remediation

## Quick Start

```bash
# Clone or create project
git clone <your-repo> preflight-sec
cd preflight-sec

# Make script executable
chmod +x run.sh

# Run scan (replace with your test target)
./run.sh https://your-staging-app.com --login-url /login --username test --password test123