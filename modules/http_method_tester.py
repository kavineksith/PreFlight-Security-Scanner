"""
HTTP Method & Status Code Security Tester
Tests dangerous methods, verb tampering, status code bypass, open redirects, protocol downgrade.
"""

from urllib.parse import urljoin, urlparse
from colorama import Fore, Style


class HTTPMethodTester:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []

    def run_all_checks(self):
        print(f"{Fore.CYAN}[*] HTTP Method & Status Code Security Testing{Style.RESET_ALL}")
        self.test_dangerous_methods()
        self.test_method_override()
        self.test_verb_tampering_auth()
        self.test_status_code_info_leak()
        self.test_open_redirects()
        self.test_protocol_downgrade()
        return self.findings

    def test_dangerous_methods(self):
        print(f"{Fore.YELLOW}[*] Testing dangerous HTTP methods...{Style.RESET_ALL}")
        methods = ['TRACE', 'PUT', 'DELETE', 'CONNECT', 'PATCH', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE']
        for method in methods:
            try:
                r = self.session.request(method, self.base_url, timeout=5)
                if r.status_code not in (405, 501, 403, 404):
                    sev = 'HIGH' if method == 'TRACE' else 'MEDIUM'
                    desc = f'{method} method enabled — '
                    if method == 'TRACE':
                        desc += 'can be used for Cross-Site Tracing (XST) attacks'
                    elif method in ('PUT', 'DELETE'):
                        desc += 'may allow unauthorized file modification/deletion'
                    elif method == 'CONNECT':
                        desc += 'may allow proxy tunneling through the server'
                    else:
                        desc += 'may enable WebDAV operations'
                    self.findings.append({
                        'title': f'Dangerous HTTP Method Enabled: {method}',
                        'description': desc,
                        'severity': sev, 'category': 'http_methods',
                        'owasp': 'A05:2021', 'cwe': 'CWE-749',
                        'remediation': f'Disable {method} method in web server configuration',
                        'evidence': f'{method} / returned {r.status_code}'
                    })
            except Exception:
                continue

    def test_method_override(self):
        print(f"{Fore.YELLOW}[*] Testing method override headers...{Style.RESET_ALL}")
        protected = ['/admin', '/api/admin', '/settings']
        override_headers = [
            ('X-HTTP-Method-Override', 'GET'),
            ('X-HTTP-Method', 'GET'),
            ('X-Method-Override', 'GET'),
            ('_method', 'GET'),  # Some frameworks use this as a param
        ]
        for path in protected:
            url = urljoin(self.base_url, path)
            for header, value in override_headers:
                try:
                    r = self.session.post(url, headers={header: value}, data={}, timeout=5)
                    if r.status_code == 200:
                        self.findings.append({
                            'title': f'HTTP Method Override Accepted: {header}',
                            'description': f'{header}: {value} treated as GET at {path}',
                            'severity': 'MEDIUM', 'category': 'http_methods',
                            'cwe': 'CWE-650',
                            'remediation': 'Disable method override headers or restrict their use',
                            'evidence': f'POST {path} with {header}: {value} returned 200'
                        })
                        return
                except Exception:
                    continue

    def test_verb_tampering_auth(self):
        print(f"{Fore.YELLOW}[*] Testing verb tampering auth bypass...{Style.RESET_ALL}")
        protected = ['/admin', '/api/admin/users', '/admin/settings', '/api/internal']
        for path in protected:
            url = urljoin(self.base_url, path)
            responses = {}
            for method in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']:
                try:
                    r = self.session.request(method, url, timeout=5)
                    responses[method] = r.status_code
                except Exception:
                    responses[method] = None
            # If GET is blocked but other methods succeed
            if responses.get('GET') in (401, 403):
                bypassed = [m for m, s in responses.items() if s == 200 and m != 'GET']
                if bypassed:
                    self.findings.append({
                        'title': 'Auth Bypass via Verb Tampering',
                        'description': f'{path}: GET blocked ({responses["GET"]}) but {bypassed[0]} returns 200',
                        'severity': 'HIGH', 'category': 'http_methods',
                        'owasp': 'A01:2021', 'cwe': 'CWE-650',
                        'remediation': 'Apply access control uniformly across all HTTP methods',
                        'evidence': f'GET={responses["GET"]}, {bypassed[0]}=200 at {path}'
                    })
                    return

    def test_status_code_info_leak(self):
        print(f"{Fore.YELLOW}[*] Testing status code information leakage...{Style.RESET_ALL}")
        tests = [
            ('/admin', '401/403 for admin'),
            ('/api/users/99999', '404 for nonexistent user'),
            ('/api/internal', '403 for internal API'),
        ]
        for path, desc in tests:
            try:
                url = urljoin(self.base_url, path)
                r = self.session.get(url, timeout=5)
                # Verbose error pages
                if r.status_code in (401, 403, 500):
                    error_indicators = ['stack', 'traceback', 'exception', 'debug',
                                        'detailed', 'sql', 'file "', 'line ']
                    if any(ind in r.text.lower() for ind in error_indicators):
                        self.findings.append({
                            'title': f'Information Leak in {r.status_code} Response',
                            'description': f'Verbose error at {path} reveals internal details',
                            'severity': 'MEDIUM', 'category': 'http_methods',
                            'owasp': 'A05:2021', 'cwe': 'CWE-209',
                            'remediation': 'Use generic error pages, suppress stack traces in production',
                            'evidence': f'{r.status_code} at {path} contains debug information'
                        })
                        return
            except Exception:
                continue

    def test_open_redirects(self):
        print(f"{Fore.YELLOW}[*] Testing open redirects...{Style.RESET_ALL}")
        redirect_params = ['url', 'redirect', 'next', 'return', 'returnUrl', 'redirect_uri',
                           'continue', 'dest', 'destination', 'goto', 'out', 'ref']
        evil_urls = ['https://evil.com', '//evil.com', 'https://evil.com%2f%2f', '/\\evil.com']
        for param in redirect_params:
            for evil in evil_urls:
                try:
                    url = f"{self.base_url}/redirect?{param}={evil}"
                    r = self.session.get(url, timeout=5, allow_redirects=False)
                    if r.status_code in (301, 302, 307, 308):
                        loc = r.headers.get('Location', '')
                        if urlparse(loc).netloc == 'evil.com':
                            self.findings.append({
                                'title': 'Open Redirect Vulnerability',
                                'description': f'Open redirect via {param} parameter',
                                'severity': 'MEDIUM', 'category': 'http_methods',
                                'owasp': 'A01:2021', 'cwe': 'CWE-601',
                                'remediation': 'Validate redirect URLs against an allowlist of trusted domains',
                                'evidence': f'?{param}={evil} -> Location: {loc}',
                                'mitre_attack': 'T1036'
                            })
                            return
                except Exception:
                    continue

    def test_protocol_downgrade(self):
        print(f"{Fore.YELLOW}[*] Testing protocol downgrade...{Style.RESET_ALL}")
        if not self.base_url.startswith('https'):
            self.findings.append({
                'title': 'No HTTPS Configured',
                'description': 'Target does not use HTTPS — all traffic in plaintext',
                'severity': 'HIGH', 'category': 'http_methods',
                'cwe': 'CWE-319',
                'remediation': 'Enable HTTPS and redirect all HTTP traffic',
                'evidence': f'Target URL: {self.base_url}'
            })
            return
        http_url = self.base_url.replace('https://', 'http://')
        try:
            r = self.session.get(http_url, timeout=5, allow_redirects=False)
            if r.status_code not in (301, 302, 307, 308):
                self.findings.append({
                    'title': 'No HTTP to HTTPS Redirect',
                    'description': 'HTTP requests not redirected to HTTPS',
                    'severity': 'MEDIUM', 'category': 'http_methods',
                    'cwe': 'CWE-319',
                    'remediation': 'Configure permanent redirect from HTTP to HTTPS',
                    'evidence': f'HTTP request returned {r.status_code} instead of redirect'
                })
            elif r.status_code in (301, 302, 307, 308):
                loc = r.headers.get('Location', '')
                if not loc.startswith('https'):
                    self.findings.append({
                        'title': 'HTTP Redirect Not to HTTPS',
                        'description': f'HTTP redirects to non-HTTPS: {loc}',
                        'severity': 'MEDIUM', 'category': 'http_methods',
                        'cwe': 'CWE-319',
                        'remediation': 'Ensure HTTP always redirects to HTTPS',
                        'evidence': f'HTTP -> {loc}'
                    })
        except Exception:
            pass
