"""
CORS Misconfiguration Tester
Tests for Cross-Origin Resource Sharing security issues.
"""

from urllib.parse import urlparse
from colorama import Fore, Style


class CORSTester:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.hostname = urlparse(base_url).hostname or ''
        self.findings = []

    def run_all_checks(self):
        """Run all CORS tests."""
        print(f"{Fore.CYAN}[*] CORS Security Testing{Style.RESET_ALL}")

        self.test_wildcard_origin()
        self.test_null_origin()
        self.test_reflected_origin()
        self.test_subdomain_origin()
        self.test_credentials_with_wildcard()
        self.test_preflight_bypass()

        return self.findings

    def _send_cors_request(self, origin, method='GET'):
        """Send a request with a specific Origin header."""
        headers = {
            'Origin': origin,
            'Access-Control-Request-Method': method,
            'Access-Control-Request-Headers': 'Authorization'
        }
        try:
            response = self.session.options(self.base_url, headers=headers, timeout=5)
            return response
        except Exception:
            return None

    def test_wildcard_origin(self):
        """Test if CORS allows wildcard * origin."""
        print(f"{Fore.YELLOW}[*] Testing wildcard CORS origin...{Style.RESET_ALL}")

        try:
            response = self._send_cors_request('https://evil.com')
            if response and response.headers.get('Access-Control-Allow-Origin') == '*':
                self.findings.append({
                    'title': 'CORS Wildcard Origin Allowed',
                    'description': 'Server responds with Access-Control-Allow-Origin: * for any origin',
                    'severity': 'HIGH',
                    'category': 'cors',
                    'owasp': 'A05:2021',
                    'cwe': 'CWE-942',
                    'remediation': 'Restrict Access-Control-Allow-Origin to specific trusted domains',
                    'evidence': 'ACAO: * returned for evil.com origin'
                })
        except Exception:
            pass

    def test_null_origin(self):
        """Test if null origin is accepted."""
        print(f"{Fore.YELLOW}[*] Testing null origin...{Style.RESET_ALL}")

        try:
            response = self._send_cors_request('null')
            if response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                if acao == 'null':
                    self.findings.append({
                        'title': 'CORS Null Origin Accepted',
                        'description': 'Server accepts "null" as a valid origin — exploitable via sandboxed iframes',
                        'severity': 'HIGH',
                        'category': 'cors',
                        'owasp': 'A05:2021',
                        'cwe': 'CWE-942',
                        'remediation': 'Never reflect "null" as Access-Control-Allow-Origin',
                        'evidence': 'ACAO: null returned'
                    })
        except Exception:
            pass

    def test_reflected_origin(self):
        """Test if origin is reflected back without validation."""
        print(f"{Fore.YELLOW}[*] Testing reflected origin...{Style.RESET_ALL}")

        test_origins = [
            'https://evil.com',
            'https://attacker.example.com',
            f'https://{self.hostname}.evil.com'
        ]

        for origin in test_origins:
            try:
                response = self._send_cors_request(origin)
                if response:
                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                    if acao == origin:
                        self.findings.append({
                            'title': 'CORS Origin Reflection',
                            'description': f'Server reflects arbitrary origin: {origin}',
                            'severity': 'HIGH',
                            'category': 'cors',
                            'owasp': 'A05:2021',
                            'cwe': 'CWE-942',
                            'remediation': 'Validate origin against an allowlist, do not reflect blindly',
                            'evidence': f'Sent Origin: {origin}, received ACAO: {acao}'
                        })
                        return
            except Exception:
                continue

    def test_subdomain_origin(self):
        """Test if subdomains of target are allowed."""
        print(f"{Fore.YELLOW}[*] Testing subdomain origin...{Style.RESET_ALL}")

        evil_subdomain = f'https://evil.{self.hostname}'
        try:
            response = self._send_cors_request(evil_subdomain)
            if response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                if acao == evil_subdomain:
                    self.findings.append({
                        'title': 'CORS Subdomain Bypass',
                        'description': f'Arbitrary subdomain origin accepted: {evil_subdomain}',
                        'severity': 'MEDIUM',
                        'category': 'cors',
                        'owasp': 'A05:2021',
                        'cwe': 'CWE-942',
                        'remediation': 'Validate full origin, not just domain suffix match',
                        'evidence': f'Origin {evil_subdomain} accepted'
                    })
        except Exception:
            pass

    def test_credentials_with_wildcard(self):
        """Test if credentials are allowed with wildcard origin."""
        print(f"{Fore.YELLOW}[*] Testing credentials with wildcard...{Style.RESET_ALL}")

        try:
            response = self._send_cors_request('https://evil.com')
            if response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')

                if acao == '*' and acac.lower() == 'true':
                    self.findings.append({
                        'title': 'CORS Credentials with Wildcard',
                        'description': 'Allow-Credentials: true with wildcard origin — maximum exposure',
                        'severity': 'CRITICAL',
                        'category': 'cors',
                        'owasp': 'A05:2021',
                        'cwe': 'CWE-942',
                        'remediation': 'Never combine Access-Control-Allow-Credentials: true with wildcard origin',
                        'evidence': 'ACAO: * with ACAC: true'
                    })
                elif acac.lower() == 'true' and acao not in ('', '*'):
                    self.findings.append({
                        'title': 'CORS Credentials with Reflected Origin',
                        'description': f'Credentials allowed with reflected origin: {acao}',
                        'severity': 'HIGH',
                        'category': 'cors',
                        'cwe': 'CWE-942',
                        'remediation': 'Restrict credentialed CORS to a strict allowlist of trusted origins',
                        'evidence': f'ACAO: {acao}, ACAC: true'
                    })
        except Exception:
            pass

    def test_preflight_bypass(self):
        """Test if preflight checks can be bypassed."""
        print(f"{Fore.YELLOW}[*] Testing preflight bypass...{Style.RESET_ALL}")

        # Test with non-standard method without preflight
        try:
            headers = {'Origin': 'https://evil.com', 'Content-Type': 'text/plain'}
            response = self.session.post(self.base_url, headers=headers, data='test', timeout=5)
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            if acao in ('*', 'https://evil.com'):
                self.findings.append({
                    'title': 'CORS Preflight Bypass',
                    'description': 'Simple requests bypass preflight and CORS headers are returned',
                    'severity': 'MEDIUM',
                    'category': 'cors',
                    'remediation': 'Ensure CORS validation on all endpoints, not just preflight',
                    'evidence': f'POST with text/plain returned ACAO: {acao}'
                })
        except Exception:
            pass
