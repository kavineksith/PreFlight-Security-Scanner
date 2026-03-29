"""
Rate Limiting & Brute-Force Tester
Tests login brute-force, API rate limits, account lockout, and CAPTCHA.
"""

import time
from urllib.parse import urljoin
from colorama import Fore, Style


class RateLimiterTester:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []

    def run_all_checks(self):
        print(f"{Fore.CYAN}[*] Rate Limiting & Brute-Force Testing{Style.RESET_ALL}")
        self.test_login_rate_limiting()
        self.test_api_rate_limiting()
        self.test_account_lockout()
        self.test_captcha_presence()
        self.test_ip_based_bypass()
        return self.findings

    def test_login_rate_limiting(self):
        print(f"{Fore.YELLOW}[*] Testing login rate limiting...{Style.RESET_ALL}")
        login_url = urljoin(self.base_url, '/login')
        success = 0
        start = time.time()
        for i in range(30):
            try:
                r = self.session.post(login_url, data={'username': f'test{i}', 'password': 'wrong'}, timeout=2)
                if r.status_code != 429:
                    success += 1
            except Exception:
                pass
        elapsed = time.time() - start
        if success > 25 and elapsed < 15:
            self.findings.append({
                'title': 'No Login Rate Limiting',
                'description': f'{success}/30 login attempts succeeded without rate limiting in {elapsed:.1f}s',
                'severity': 'HIGH', 'category': 'rate_limiting',
                'owasp': 'A07:2021', 'cwe': 'CWE-307',
                'remediation': 'Implement rate limiting: max 5 failed attempts per minute per IP/account',
                'evidence': f'{success} attempts without 429 in {elapsed:.1f}s',
                'mitre_attack': 'T1110'
            })

    def test_api_rate_limiting(self):
        print(f"{Fore.YELLOW}[*] Testing API rate limiting...{Style.RESET_ALL}")
        endpoints = ['/api/users', '/api/search', '/api/products']
        for ep in endpoints:
            url = urljoin(self.base_url, ep)
            success = 0
            start = time.time()
            for i in range(50):
                try:
                    r = self.session.get(url, timeout=1)
                    if r.status_code != 429:
                        success += 1
                except Exception:
                    pass
            elapsed = time.time() - start
            if success > 45 and elapsed < 10:
                self.findings.append({
                    'title': f'No API Rate Limiting: {ep}',
                    'description': f'{success}/50 requests to {ep} without rate limiting',
                    'severity': 'MEDIUM', 'category': 'rate_limiting',
                    'api_owasp': 'API4:2023', 'cwe': 'CWE-770',
                    'remediation': 'Implement rate limiting per user/IP on all API endpoints',
                    'evidence': f'{success}/50 requests in {elapsed:.1f}s without 429'
                })
                return

    def test_account_lockout(self):
        print(f"{Fore.YELLOW}[*] Testing account lockout...{Style.RESET_ALL}")
        login_url = urljoin(self.base_url, '/login')
        locked = False
        for i in range(15):
            try:
                r = self.session.post(login_url, data={'username': 'admin', 'password': f'wrong{i}'}, timeout=3)
                if r.status_code == 423 or 'locked' in r.text.lower() or 'too many' in r.text.lower():
                    locked = True
                    break
            except Exception:
                pass
        if not locked:
            self.findings.append({
                'title': 'No Account Lockout Mechanism',
                'description': '15 failed login attempts without account lockout',
                'severity': 'MEDIUM', 'category': 'rate_limiting',
                'owasp': 'A07:2021', 'cwe': 'CWE-307',
                'remediation': 'Lock accounts after 5 failed attempts, implement progressive delays',
                'evidence': '15 consecutive failed logins without lockout',
                'mitre_attack': 'T1110'
            })

    def test_captcha_presence(self):
        print(f"{Fore.YELLOW}[*] Checking CAPTCHA presence...{Style.RESET_ALL}")
        try:
            r = self.session.get(urljoin(self.base_url, '/login'), timeout=5)
            captcha_indicators = ['captcha', 'recaptcha', 'hcaptcha', 'turnstile', 'g-recaptcha']
            if not any(ind in r.text.lower() for ind in captcha_indicators):
                self.findings.append({
                    'title': 'No CAPTCHA on Login',
                    'description': 'Login page has no CAPTCHA — vulnerable to automated brute-force',
                    'severity': 'MEDIUM', 'category': 'rate_limiting',
                    'remediation': 'Add CAPTCHA (reCAPTCHA/hCaptcha) after failed login attempts',
                    'evidence': 'No CAPTCHA elements found on login page'
                })
        except Exception:
            pass

    def test_ip_based_bypass(self):
        print(f"{Fore.YELLOW}[*] Testing IP-based rate limit bypass...{Style.RESET_ALL}")
        bypass_headers = {
            'X-Forwarded-For': '1.2.3.4',
            'X-Real-IP': '5.6.7.8',
            'X-Originating-IP': '9.10.11.12',
            'X-Client-IP': '13.14.15.16',
            'True-Client-IP': '17.18.19.20',
        }
        login_url = urljoin(self.base_url, '/login')
        for header, ip in bypass_headers.items():
            try:
                r = self.session.post(login_url, data={'username': 'admin', 'password': 'wrong'},
                                      headers={header: ip}, timeout=3)
                if r.status_code != 429:
                    # This is just informational — can't confirm bypass without first triggering rate limit
                    pass
            except Exception:
                continue
        self.findings.append({
            'title': 'Rate Limit IP Bypass Review',
            'description': 'Verify rate limiting is not solely IP-based and cannot be bypassed via X-Forwarded-For',
            'severity': 'INFO', 'category': 'rate_limiting',
            'remediation': 'Do not trust X-Forwarded-For for rate limiting, use authenticated user identity',
            'evidence': 'Manual verification required for IP-based bypass'
        })
