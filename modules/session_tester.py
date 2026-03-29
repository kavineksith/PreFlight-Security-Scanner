"""
Session Security & Cookie Hijacking Tester
Tests session fixation, entropy, logout, concurrent sessions, and transport.
"""

import re
import math
import hashlib
from collections import Counter
from urllib.parse import urljoin
from colorama import Fore, Style


class SessionTester:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []

    def run_all_checks(self, is_authenticated=False, username=None, password=None):
        """Run all session security checks."""
        print(f"{Fore.CYAN}[*] Session & Cookie Security Testing{Style.RESET_ALL}")
        self.test_session_fixation(username, password)
        self.test_session_id_entropy()
        self.test_cookie_scope()
        self.test_session_logout_invalidation()
        self.test_secure_transport()
        self.test_cookie_theft_vectors()
        self.test_session_riding()
        return self.findings

    def _get_session_cookies(self):
        names = ['session', 'sessionid', 'sid', 'phpsessid', 'jsessionid',
                 'connect.sid', 'asp.net_sessionid', 'token', 'auth']
        return [c for c in self.session.cookies if any(s in c.name.lower() for s in names)]

    def test_session_fixation(self, username=None, password=None):
        print(f"{Fore.YELLOW}[*] Testing session fixation...{Style.RESET_ALL}")
        try:
            self.session.get(self.base_url, timeout=5)
            pre = {c.name: c.value for c in self.session.cookies}
            if username and password:
                self.session.post(urljoin(self.base_url, '/login'),
                                 data={'username': username, 'password': password}, timeout=5)
                post = {c.name: c.value for c in self.session.cookies}
                unchanged = [n for n, v in pre.items()
                             if n in post and post[n] == v and 'session' in n.lower()]
                if unchanged:
                    self.findings.append({
                        'title': 'Session Fixation Vulnerability',
                        'description': f'Session unchanged after auth: {", ".join(unchanged)}',
                        'severity': 'HIGH', 'category': 'session',
                        'owasp': 'A07:2021', 'cwe': 'CWE-384',
                        'remediation': 'Regenerate session ID after successful authentication',
                        'evidence': f'Cookies unchanged: {unchanged}',
                        'mitre_attack': 'T1563'
                    })
        except Exception:
            pass

    def test_session_id_entropy(self):
        print(f"{Fore.YELLOW}[*] Analyzing session ID entropy...{Style.RESET_ALL}")
        try:
            self.session.get(self.base_url, timeout=5)
        except Exception:
            pass
        for cookie in self._get_session_cookies():
            val = cookie.value
            issues = []
            if len(val) < 16:
                issues.append(f"Too short ({len(val)} chars)")
            entropy = self._calc_entropy(val)
            if entropy < 3.0:
                issues.append(f"Low entropy ({entropy:.2f})")
            if re.match(r'^\d+$', val):
                issues.append("Numeric only — predictable")
            if issues:
                self.findings.append({
                    'title': f'Weak Session ID: {cookie.name}',
                    'description': 'Session ID has insufficient randomness',
                    'severity': 'HIGH', 'category': 'session',
                    'owasp': 'A07:2021', 'cwe': 'CWE-330',
                    'remediation': 'Use CSPRNG for 128+ bit session IDs',
                    'evidence': f'{cookie.name} ({len(val)} chars, {entropy:.2f} entropy) | {"; ".join(issues)}',
                    'mitre_attack': 'T1539'
                })

    def _calc_entropy(self, data):
        if not data:
            return 0.0
        c = Counter(data)
        l = len(data)
        return -sum((n/l) * math.log2(n/l) for n in c.values())

    def test_cookie_scope(self):
        print(f"{Fore.YELLOW}[*] Checking cookie scope...{Style.RESET_ALL}")
        for cookie in self.session.cookies:
            issues = []
            if cookie.domain and cookie.domain.startswith('.') and cookie.domain.count('.') <= 1:
                issues.append(f"Broad domain: {cookie.domain}")
            if not cookie.secure:
                issues.append("Missing Secure flag")
            if issues:
                self.findings.append({
                    'title': f'Cookie Scope Issue: {cookie.name}',
                    'description': f'Cookie has permissive scope',
                    'severity': 'MEDIUM', 'category': 'session', 'cwe': 'CWE-1004',
                    'remediation': 'Restrict cookie domain/path to minimum scope',
                    'evidence': f'Domain: {cookie.domain}, Path: {cookie.path} | {"; ".join(issues)}'
                })

    def test_session_logout_invalidation(self):
        print(f"{Fore.YELLOW}[*] Testing logout invalidation...{Style.RESET_ALL}")
        pre = {c.name: c.value for c in self.session.cookies}
        for path in ['/logout', '/api/logout', '/signout']:
            try:
                self.session.get(urljoin(self.base_url, path), timeout=5)
            except Exception:
                continue
        if pre:
            import requests as req
            s = req.Session()
            for n, v in pre.items():
                s.cookies.set(n, v)
            for page in ['/profile', '/dashboard', '/account']:
                try:
                    r = s.get(urljoin(self.base_url, page), timeout=5)
                    if r.status_code == 200 and 'login' not in r.url.lower():
                        self.findings.append({
                            'title': 'Session Not Invalidated on Logout',
                            'description': f'Old session valid after logout — accessed {page}',
                            'severity': 'HIGH', 'category': 'session',
                            'owasp': 'A07:2021', 'cwe': 'CWE-613',
                            'remediation': 'Invalidate session server-side on logout',
                            'evidence': f'Accessed {page} with pre-logout cookies',
                            'mitre_attack': 'T1539'
                        })
                        return
                except Exception:
                    continue

    def test_secure_transport(self):
        print(f"{Fore.YELLOW}[*] Testing secure transport...{Style.RESET_ALL}")
        for c in self._get_session_cookies():
            if not c.secure:
                self.findings.append({
                    'title': f'Insecure Cookie Transport: {c.name}',
                    'description': f'Cookie lacks Secure flag — sent over HTTP',
                    'severity': 'HIGH', 'category': 'session',
                    'owasp': 'A02:2021', 'cwe': 'CWE-614',
                    'remediation': 'Set Secure flag on all session cookies',
                    'evidence': f'{c.name}: Secure=False', 'mitre_attack': 'T1557'
                })

    def test_cookie_theft_vectors(self):
        print(f"{Fore.YELLOW}[*] Testing cookie theft vectors...{Style.RESET_ALL}")
        for c in self._get_session_cookies():
            has_httponly = hasattr(c, '_rest') and any(k.lower() == 'httponly' for k in c._rest)
            if not has_httponly:
                self.findings.append({
                    'title': f'Cookie Stealable via XSS: {c.name}',
                    'description': f'Cookie "{c.name}" missing HttpOnly',
                    'severity': 'HIGH', 'category': 'session',
                    'owasp': 'A07:2021', 'cwe': 'CWE-1004',
                    'remediation': 'Set HttpOnly on all session cookies',
                    'evidence': f'{c.name}: HttpOnly=False', 'mitre_attack': 'T1539'
                })

    def test_session_riding(self):
        print(f"{Fore.YELLOW}[*] Testing session riding...{Style.RESET_ALL}")
        for c in self._get_session_cookies():
            samesite = None
            if hasattr(c, '_rest'):
                for k in c._rest:
                    if k.lower() == 'samesite':
                        samesite = c._rest[k]
            if not samesite or samesite.lower() == 'none':
                self.findings.append({
                    'title': f'Session Riding Risk: {c.name}',
                    'description': f'Cookie vulnerable to cross-site riding',
                    'severity': 'MEDIUM', 'category': 'session', 'cwe': 'CWE-352',
                    'remediation': 'Set SameSite=Strict/Lax and use CSRF tokens',
                    'evidence': f'{c.name}: SameSite={samesite or "not set"}'
                })
