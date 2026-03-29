"""
CSRF Protection Analyzer
Tests for Cross-Site Request Forgery vulnerabilities.
"""

import re
import hashlib
from urllib.parse import urljoin
from colorama import Fore, Style


class CSRFTester:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []

    def run_all_checks(self):
        """Run all CSRF tests."""
        print(f"{Fore.CYAN}[*] CSRF Protection Analysis{Style.RESET_ALL}")

        self.test_token_presence()
        self.test_token_randomness()
        self.test_samesite_cookies()
        self.test_referer_origin_bypass()
        self.test_token_reuse()
        self.test_method_override()

        return self.findings

    def _fetch_page(self, path='/'):
        """Fetch a page and return response."""
        try:
            return self.session.get(urljoin(self.base_url, path), timeout=10)
        except Exception:
            return None

    def _extract_csrf_tokens(self, html):
        """Extract CSRF tokens from HTML forms."""
        tokens = []
        # Look for hidden inputs with CSRF-like names
        patterns = [
            r'name=["\'](?:csrf|_csrf|csrfmiddlewaretoken|_token|__RequestVerificationToken|authenticity_token)["\'].*?value=["\']([^"\']+)["\']',
            r'value=["\']([^"\']+)["\'].*?name=["\'](?:csrf|_csrf|csrfmiddlewaretoken|_token)["\']',
        ]
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            tokens.extend(matches)

        # Look for meta tags with CSRF tokens
        meta_patterns = [
            r'<meta\s+name=["\']csrf-token["\'].*?content=["\']([^"\']+)["\']',
            r'<meta\s+content=["\']([^"\']+)["\'].*?name=["\']csrf-token["\']',
        ]
        for pattern in meta_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            tokens.extend(matches)

        return tokens

    def test_token_presence(self):
        """Check if forms have CSRF tokens."""
        print(f"{Fore.YELLOW}[*] Checking CSRF token presence...{Style.RESET_ALL}")

        test_pages = ['/', '/login', '/profile', '/settings', '/account', '/contact']

        for page in test_pages:
            response = self._fetch_page(page)
            if not response or response.status_code != 200:
                continue

            # Check if page has forms
            forms = re.findall(r'<form[^>]*method=["\']post["\'][^>]*>.*?</form>', response.text, re.DOTALL | re.IGNORECASE)
            if forms:
                tokens = self._extract_csrf_tokens(response.text)
                if not tokens:
                    self.findings.append({
                        'title': 'Missing CSRF Token in Forms',
                        'description': f'POST form at {page} has no CSRF token',
                        'severity': 'HIGH',
                        'category': 'csrf',
                        'owasp': 'A01:2021',
                        'cwe': 'CWE-352',
                        'remediation': 'Add unique, unpredictable CSRF tokens to all state-changing forms',
                        'evidence': f'Found {len(forms)} POST form(s) at {page} without CSRF tokens'
                    })
                    return

    def test_token_randomness(self):
        """Check if CSRF tokens are properly random."""
        print(f"{Fore.YELLOW}[*] Testing CSRF token randomness...{Style.RESET_ALL}")

        tokens_collected = []
        for _ in range(3):
            response = self._fetch_page('/login')
            if response and response.status_code == 200:
                tokens = self._extract_csrf_tokens(response.text)
                tokens_collected.extend(tokens)

        if len(tokens_collected) >= 2:
            # Check for duplicate tokens
            unique_tokens = set(tokens_collected)
            if len(unique_tokens) == 1:
                self.findings.append({
                    'title': 'Static CSRF Token',
                    'description': 'CSRF token does not change between requests — predictable',
                    'severity': 'HIGH',
                    'category': 'csrf',
                    'owasp': 'A01:2021',
                    'cwe': 'CWE-330',
                    'remediation': 'Generate a new, cryptographically random CSRF token per session/request',
                    'evidence': f'Same token returned {len(tokens_collected)} times: {tokens_collected[0][:20]}...'
                })

            # Check token length (short tokens are weak)
            for token in unique_tokens:
                if len(token) < 16:
                    self.findings.append({
                        'title': 'Short CSRF Token',
                        'description': f'CSRF token length is {len(token)} chars — may be brute-forceable',
                        'severity': 'MEDIUM',
                        'category': 'csrf',
                        'cwe': 'CWE-330',
                        'remediation': 'Use CSRF tokens of at least 32 characters with high entropy',
                        'evidence': f'Token: {token}'
                    })
                    break

    def test_samesite_cookies(self):
        """Check SameSite attribute on session cookies."""
        print(f"{Fore.YELLOW}[*] Checking SameSite cookie attribute...{Style.RESET_ALL}")

        session_names = ['sessionid', 'session', 'sid', 'phpsessid', 'jsessionid', 'connect.sid', 'asp.net_sessionid']

        for cookie in self.session.cookies:
            if cookie.name.lower() in session_names or 'session' in cookie.name.lower():
                samesite = None
                for key in cookie._rest:
                    if key.lower() == 'samesite':
                        samesite = cookie._rest[key]

                if not samesite or samesite.lower() == 'none':
                    self.findings.append({
                        'title': 'Session Cookie Missing SameSite',
                        'description': f'Session cookie "{cookie.name}" has SameSite={samesite or "not set"} — vulnerable to CSRF',
                        'severity': 'MEDIUM',
                        'category': 'csrf',
                        'owasp': 'A01:2021',
                        'cwe': 'CWE-1275',
                        'remediation': 'Set SameSite=Strict or SameSite=Lax on all session cookies',
                        'evidence': f'Cookie: {cookie.name}, SameSite: {samesite or "absent"}'
                    })

    def test_referer_origin_bypass(self):
        """Test if CSRF protection can be bypassed by manipulating Referer/Origin."""
        print(f"{Fore.YELLOW}[*] Testing Referer/Origin bypass...{Style.RESET_ALL}")

        test_endpoints = ['/profile', '/settings', '/account/update']

        for endpoint in test_endpoints:
            url = urljoin(self.base_url, endpoint)

            bypass_headers = [
                {'Referer': ''},
                {'Referer': 'https://evil.com'},
                {'Origin': 'https://evil.com'},
                {},  # No Referer/Origin
            ]

            for headers in bypass_headers:
                try:
                    response = self.session.post(url, data={'test': 'value'}, headers=headers, timeout=5)
                    if response.status_code in (200, 201, 302):
                        if 'error' not in response.text.lower() and 'forbidden' not in response.text.lower():
                            self.findings.append({
                                'title': 'CSRF Referer/Origin Bypass',
                                'description': f'State-changing request at {endpoint} accepted without valid Referer/Origin',
                                'severity': 'MEDIUM',
                                'category': 'csrf',
                                'owasp': 'A01:2021',
                                'cwe': 'CWE-352',
                                'remediation': 'Validate both CSRF token AND Origin/Referer headers',
                                'evidence': f'POST {endpoint} with headers {headers} returned {response.status_code}'
                            })
                            return
                except Exception:
                    continue

    def test_token_reuse(self):
        """Test if CSRF tokens can be reused across sessions."""
        print(f"{Fore.YELLOW}[*] Testing CSRF token reuse...{Style.RESET_ALL}")

        response = self._fetch_page('/login')
        if not response or response.status_code != 200:
            return

        tokens = self._extract_csrf_tokens(response.text)
        if tokens:
            # Try using the same token in a new session
            import requests
            new_session = requests.Session()
            try:
                new_response = new_session.post(
                    urljoin(self.base_url, '/login'),
                    data={'csrf': tokens[0], '_token': tokens[0], 'username': 'test', 'password': 'test'},
                    timeout=5
                )
                if new_response.status_code in (200, 302):
                    if 'invalid' not in new_response.text.lower() and 'csrf' not in new_response.text.lower():
                        self.findings.append({
                            'title': 'CSRF Token Reusable Across Sessions',
                            'description': 'CSRF token from one session accepted in another',
                            'severity': 'HIGH',
                            'category': 'csrf',
                            'cwe': 'CWE-352',
                            'remediation': 'Bind CSRF tokens to user sessions and invalidate on use',
                            'evidence': f'Token {tokens[0][:20]}... accepted in different session'
                        })
            except Exception:
                pass

    def test_method_override(self):
        """Test if HTTP method override bypasses CSRF checks."""
        print(f"{Fore.YELLOW}[*] Testing method override bypass...{Style.RESET_ALL}")

        test_endpoints = ['/settings', '/profile']

        for endpoint in test_endpoints:
            url = urljoin(self.base_url, endpoint)

            override_headers = [
                {'X-HTTP-Method-Override': 'GET'},
                {'X-Method-Override': 'GET'},
                {'X-HTTP-Method': 'GET'},
            ]

            for headers in override_headers:
                try:
                    response = self.session.post(url, data={'test': 'value'}, headers=headers, timeout=5)
                    if response.status_code in (200, 201):
                        self.findings.append({
                            'title': 'CSRF Bypass via Method Override',
                            'description': f'Method override header bypasses CSRF protection at {endpoint}',
                            'severity': 'MEDIUM',
                            'category': 'csrf',
                            'cwe': 'CWE-352',
                            'remediation': 'Ignore or restrict X-HTTP-Method-Override headers',
                            'evidence': f'POST {endpoint} with {headers} treated as GET'
                        })
                        return
                except Exception:
                    continue
