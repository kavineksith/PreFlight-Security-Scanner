"""
Authentication Bypass & MFA Tester
Tests MFA bypass, password reset abuse, OAuth misconfig, verb/path tampering.
"""

from urllib.parse import urljoin, quote, urlparse
from colorama import Fore, Style


class AuthBypassTester:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []

    def run_all_checks(self):
        print(f"{Fore.CYAN}[*] Authentication Bypass & MFA Testing{Style.RESET_ALL}")
        self.test_mfa_bypass()
        self.test_password_reset_abuse()
        self.test_verb_tampering()
        self.test_path_bypass()
        self.test_header_auth_bypass()
        self.test_oauth_misconfig()
        return self.findings

    def test_mfa_bypass(self):
        print(f"{Fore.YELLOW}[*] Testing MFA bypass...{Style.RESET_ALL}")
        bypass_paths = ['/dashboard', '/profile', '/api/me', '/account', '/home']
        for path in bypass_paths:
            try:
                r = self.session.get(urljoin(self.base_url, path), timeout=5)
                if r.status_code == 200 and 'mfa' not in r.url.lower() and '2fa' not in r.url.lower():
                    if any(k in r.text.lower() for k in ['profile', 'dashboard', 'account', 'welcome']):
                        self.findings.append({
                            'title': 'MFA Bypass via Direct Access',
                            'description': f'Protected page {path} accessible without MFA completion',
                            'severity': 'CRITICAL', 'category': 'auth_bypass',
                            'owasp': 'A07:2021', 'cwe': 'CWE-304',
                            'remediation': 'Enforce MFA check on all protected endpoints, not just login flow',
                            'evidence': f'Accessed {path} without MFA step',
                            'mitre_attack': 'T1556.006'
                        })
                        return
            except Exception:
                continue
        # Test response manipulation
        mfa_endpoints = ['/mfa/verify', '/2fa/verify', '/api/mfa/verify', '/verify-otp']
        for ep in mfa_endpoints:
            try:
                r = self.session.post(urljoin(self.base_url, ep),
                                      json={'code': '000000', 'otp': '000000'}, timeout=5)
                if r.status_code == 200 and 'success' in r.text.lower():
                    self.findings.append({
                        'title': 'MFA Bypass via Default Code',
                        'description': f'MFA at {ep} accepts default/zero code',
                        'severity': 'CRITICAL', 'category': 'auth_bypass',
                        'cwe': 'CWE-304',
                        'remediation': 'Validate MFA codes server-side, enforce time-based OTP',
                        'evidence': f'Code 000000 accepted at {ep}'
                    })
                    return
            except Exception:
                continue

    def test_password_reset_abuse(self):
        print(f"{Fore.YELLOW}[*] Testing password reset flow...{Style.RESET_ALL}")
        reset_endpoints = ['/forgot-password', '/api/forgot-password', '/password-reset', '/reset']
        for ep in reset_endpoints:
            url = urljoin(self.base_url, ep)
            # Test email enumeration
            try:
                r1 = self.session.post(url, json={'email': 'exists@test.com'}, timeout=5)
                r2 = self.session.post(url, json={'email': 'nonexistent_xyz@test.com'}, timeout=5)
                if r1.status_code != r2.status_code or abs(len(r1.text) - len(r2.text)) > 50:
                    self.findings.append({
                        'title': 'User Enumeration via Password Reset',
                        'description': f'Different responses for existing vs non-existing emails at {ep}',
                        'severity': 'MEDIUM', 'category': 'auth_bypass',
                        'owasp': 'A07:2021', 'cwe': 'CWE-204',
                        'remediation': 'Return identical responses regardless of email existence',
                        'evidence': f'Status {r1.status_code} vs {r2.status_code}, length diff {abs(len(r1.text)-len(r2.text))}'
                    })
                    return
            except Exception:
                continue

    def test_verb_tampering(self):
        print(f"{Fore.YELLOW}[*] Testing HTTP verb tampering...{Style.RESET_ALL}")
        protected = ['/admin', '/api/admin', '/admin/users', '/settings']
        for path in protected:
            url = urljoin(self.base_url, path)
            for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                try:
                    r = self.session.request(method, url, timeout=5)
                    if r.status_code == 200 and method not in ('HEAD', 'OPTIONS'):
                        self.findings.append({
                            'title': 'Auth Bypass via HTTP Verb Tampering',
                            'description': f'{method} {path} bypasses authentication',
                            'severity': 'HIGH', 'category': 'auth_bypass',
                            'owasp': 'A01:2021', 'cwe': 'CWE-650',
                            'remediation': 'Apply auth checks to all HTTP methods, not just GET/POST',
                            'evidence': f'{method} {path} returned 200'
                        })
                        return
                except Exception:
                    continue

    def test_path_bypass(self):
        print(f"{Fore.YELLOW}[*] Testing path-based auth bypass...{Style.RESET_ALL}")
        bypass_patterns = [
            '/admin/..;/', '/admin%00', '/admin/.', '/admin/./.',
            '//admin', '/./admin', '/%2e/admin', '/admin%20',
            '/admin%09', '/admin;', '/ADMIN', '/Admin',
            '/admin/~', '/admin../', '/admin..../',
        ]
        for pattern in bypass_patterns:
            try:
                url = urljoin(self.base_url, pattern)
                r = self.session.get(url, timeout=5, allow_redirects=False)
                if r.status_code == 200:
                    self.findings.append({
                        'title': 'Auth Bypass via Path Manipulation',
                        'description': f'Path "{pattern}" bypasses access control',
                        'severity': 'HIGH', 'category': 'auth_bypass',
                        'owasp': 'A01:2021', 'cwe': 'CWE-22',
                        'remediation': 'Normalize/canonicalize paths before access control checks',
                        'evidence': f'GET {pattern} returned 200'
                    })
                    return
            except Exception:
                continue

    def test_header_auth_bypass(self):
        print(f"{Fore.YELLOW}[*] Testing header-based auth bypass...{Style.RESET_ALL}")
        bypass_headers_list = [
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
        ]
        for headers in bypass_headers_list:
            try:
                r = self.session.get(self.base_url, headers=headers, timeout=5)
                if r.status_code == 200 and 'admin' in r.text.lower():
                    key = list(headers.keys())[0]
                    self.findings.append({
                        'title': f'Auth Bypass via {key} Header',
                        'description': f'Header {key} bypasses access control',
                        'severity': 'HIGH', 'category': 'auth_bypass',
                        'cwe': 'CWE-290',
                        'remediation': f'Do not trust {key} header for access control decisions',
                        'evidence': f'Header {key}: {headers[key]} granted access'
                    })
                    return
            except Exception:
                continue

    def test_oauth_misconfig(self):
        print(f"{Fore.YELLOW}[*] Testing OAuth misconfiguration...{Style.RESET_ALL}")
        oauth_endpoints = ['/oauth/callback', '/auth/callback', '/api/auth/callback',
                           '/login/oauth', '/oauth/authorize']
        for ep in oauth_endpoints:
            # Test open redirect in callback
            try:
                url = urljoin(self.base_url, f"{ep}?redirect_uri=https://evil.com")
                r = self.session.get(url, timeout=5, allow_redirects=False)
                if r.status_code in (301, 302, 307, 308):
                    loc = r.headers.get('Location', '')
                    if urlparse(loc).netloc == 'evil.com':
                        self.findings.append({
                            'title': 'OAuth Open Redirect',
                            'description': f'OAuth callback at {ep} allows redirect to external domain',
                            'severity': 'HIGH', 'category': 'auth_bypass',
                            'owasp': 'A07:2021', 'cwe': 'CWE-601',
                            'remediation': 'Validate redirect_uri against registered callback URLs',
                            'evidence': f'Redirected to: {loc}',
                            'mitre_attack': 'T1528'
                        })
                        return
            except Exception:
                continue
