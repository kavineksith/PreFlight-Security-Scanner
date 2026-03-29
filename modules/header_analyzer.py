"""
Advanced HTTP Header Security Analyzer
Full security header audit, CSP parsing, cookie attributes, fingerprint detection.
"""

import re
import requests
from urllib.parse import urlparse
from colorama import Fore, Style


class HeaderAnalyzer:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []

    def run_all_checks(self):
        """Run all header security checks."""
        print(f"{Fore.CYAN}[*] HTTP Header Security Analysis{Style.RESET_ALL}")

        try:
            self.response = self.session.get(self.base_url, timeout=10, verify=False)
            self.headers = self.response.headers
        except Exception as e:
            print(f"{Fore.RED}[✗] Could not fetch headers: {e}{Style.RESET_ALL}")
            return self.findings

        self.check_security_headers()
        self.analyze_csp()
        self.check_hsts()
        self.check_cookie_security()
        self.detect_server_fingerprint()
        self.check_information_disclosure()
        self.check_permissions_policy()
        self.check_cache_control()

        return self.findings

    def check_security_headers(self):
        """Check for presence and correctness of all security headers."""
        print(f"{Fore.YELLOW}[*] Auditing security headers...{Style.RESET_ALL}")

        required_headers = {
            'Strict-Transport-Security': {
                'severity': 'HIGH',
                'remediation': 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                'cwe': 'CWE-319'
            },
            'Content-Security-Policy': {
                'severity': 'HIGH',
                'remediation': "Add Content-Security-Policy with restrictive directives (no unsafe-inline/unsafe-eval)",
                'cwe': 'CWE-693'
            },
            'X-Frame-Options': {
                'severity': 'MEDIUM',
                'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking',
                'cwe': 'CWE-1021'
            },
            'X-Content-Type-Options': {
                'severity': 'MEDIUM',
                'remediation': 'Add X-Content-Type-Options: nosniff',
                'cwe': 'CWE-16'
            },
            'Referrer-Policy': {
                'severity': 'LOW',
                'remediation': 'Add Referrer-Policy: strict-origin-when-cross-origin',
                'cwe': 'CWE-200'
            },
            'X-XSS-Protection': {
                'severity': 'LOW',
                'remediation': 'Add X-XSS-Protection: 0 (deprecated but use CSP instead)',
                'cwe': 'CWE-79'
            },
            'Cross-Origin-Embedder-Policy': {
                'severity': 'LOW',
                'remediation': 'Add Cross-Origin-Embedder-Policy: require-corp',
                'cwe': 'CWE-346'
            },
            'Cross-Origin-Opener-Policy': {
                'severity': 'LOW',
                'remediation': 'Add Cross-Origin-Opener-Policy: same-origin',
                'cwe': 'CWE-346'
            },
            'Cross-Origin-Resource-Policy': {
                'severity': 'LOW',
                'remediation': 'Add Cross-Origin-Resource-Policy: same-origin',
                'cwe': 'CWE-346'
            }
        }

        for header, config in required_headers.items():
            if header not in self.headers:
                self.findings.append({
                    'title': f'Missing Security Header: {header}',
                    'description': f'The {header} header is not set',
                    'severity': config['severity'],
                    'category': 'headers',
                    'owasp': 'A05:2021',
                    'cwe': config['cwe'],
                    'remediation': config['remediation'],
                    'evidence': f'Header {header} absent from response'
                })

    def analyze_csp(self):
        """Parse and analyze Content-Security-Policy for weaknesses."""
        print(f"{Fore.YELLOW}[*] Analyzing CSP policy...{Style.RESET_ALL}")

        csp = self.headers.get('Content-Security-Policy', '')
        if not csp:
            return

        weaknesses = []

        if "'unsafe-inline'" in csp:
            weaknesses.append("unsafe-inline allows inline scripts/styles (XSS risk)")
        if "'unsafe-eval'" in csp:
            weaknesses.append("unsafe-eval allows eval() (code injection risk)")
        if 'data:' in csp:
            weaknesses.append("data: URI scheme allowed (potential XSS vector)")
        if '*' in csp.split():
            weaknesses.append("Wildcard (*) source allows loading from any domain")
        if 'http:' in csp:
            weaknesses.append("HTTP sources allowed (mixed content risk)")

        directives = ['default-src', 'script-src', 'style-src', 'img-src', 'connect-src',
                       'frame-src', 'object-src', 'base-uri', 'form-action']
        missing_directives = [d for d in directives if d not in csp]

        if missing_directives:
            weaknesses.append(f"Missing directives: {', '.join(missing_directives[:5])}")

        if weaknesses:
            self.findings.append({
                'title': 'Weak Content-Security-Policy',
                'description': f'CSP has {len(weaknesses)} weakness(es)',
                'severity': 'MEDIUM',
                'category': 'headers',
                'owasp': 'A05:2021',
                'cwe': 'CWE-693',
                'remediation': 'Fix CSP weaknesses: ' + '; '.join(weaknesses),
                'evidence': f'CSP: {csp[:200]}'
            })

    def check_hsts(self):
        """Check HSTS configuration and preload eligibility."""
        print(f"{Fore.YELLOW}[*] Checking HSTS configuration...{Style.RESET_ALL}")

        hsts = self.headers.get('Strict-Transport-Security', '')
        if not hsts:
            return

        issues = []

        # Check max-age
        max_age_match = re.search(r'max-age=(\d+)', hsts)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # Less than 1 year
                issues.append(f"max-age={max_age} is too short (should be >= 31536000)")
        else:
            issues.append("No max-age directive found")

        if 'includesubdomains' not in hsts.lower():
            issues.append("Missing includeSubDomains directive")

        if 'preload' not in hsts.lower():
            issues.append("Not eligible for HSTS preload (missing preload directive)")

        if issues:
            self.findings.append({
                'title': 'HSTS Configuration Issues',
                'description': 'HSTS header has configuration weaknesses',
                'severity': 'MEDIUM',
                'category': 'headers',
                'owasp': 'A05:2021',
                'cwe': 'CWE-319',
                'remediation': 'Set HSTS: max-age=31536000; includeSubDomains; preload',
                'evidence': f'HSTS: {hsts} | Issues: {"; ".join(issues)}'
            })

    def check_cookie_security(self):
        """Audit cookie security attributes."""
        print(f"{Fore.YELLOW}[*] Auditing cookie security...{Style.RESET_ALL}")

        for cookie in self.session.cookies:
            issues = []

            if not cookie.secure:
                issues.append("Missing Secure flag (sent over HTTP)")

            if 'httponly' not in str(cookie._rest).lower() and not getattr(cookie, 'has_nonstandard_attr', lambda x: False)('HttpOnly'):
                issues.append("Missing HttpOnly flag (accessible via JavaScript)")

            samesite = None
            for key in cookie._rest:
                if key.lower() == 'samesite':
                    samesite = cookie._rest[key]
            if not samesite:
                issues.append("Missing SameSite attribute (CSRF risk)")
            elif samesite.lower() == 'none':
                issues.append("SameSite=None (requires Secure flag, cross-site allowed)")

            if cookie.domain and cookie.domain.startswith('.'):
                issues.append(f"Broad domain scope: {cookie.domain}")

            if cookie.path == '/':
                pass  # Normal
            elif not cookie.path:
                issues.append("No path restriction on cookie")

            if issues:
                self.findings.append({
                    'title': f'Insecure Cookie: {cookie.name}',
                    'description': f'Cookie "{cookie.name}" has security issues',
                    'severity': 'MEDIUM',
                    'category': 'headers',
                    'owasp': 'A05:2021',
                    'cwe': 'CWE-614',
                    'remediation': 'Set Secure; HttpOnly; SameSite=Strict on all sensitive cookies',
                    'evidence': f'Cookie: {cookie.name} | Issues: {"; ".join(issues)}'
                })

    def detect_server_fingerprint(self):
        """Detect server/technology fingerprint information in headers."""
        print(f"{Fore.YELLOW}[*] Detecting server fingerprint...{Style.RESET_ALL}")

        fingerprint_headers = {
            'Server': 'Web server version disclosed',
            'X-Powered-By': 'Technology stack disclosed',
            'X-AspNet-Version': 'ASP.NET version disclosed',
            'X-AspNetMvc-Version': 'ASP.NET MVC version disclosed',
            'X-Generator': 'Site generator disclosed',
            'X-Drupal-Cache': 'Drupal CMS detected',
            'X-Varnish': 'Varnish cache server detected',
            'X-Runtime': 'Runtime information disclosed',
            'X-Version': 'Application version disclosed'
        }

        for header, message in fingerprint_headers.items():
            value = self.headers.get(header)
            if value:
                self.findings.append({
                    'title': f'Information Disclosure: {header}',
                    'description': f'{message}: {value}',
                    'severity': 'LOW',
                    'category': 'headers',
                    'owasp': 'A05:2021',
                    'cwe': 'CWE-200',
                    'remediation': f'Remove or obfuscate the {header} header',
                    'evidence': f'{header}: {value}'
                })

    def check_information_disclosure(self):
        """Check for general information disclosure in headers."""
        print(f"{Fore.YELLOW}[*] Checking information disclosure...{Style.RESET_ALL}")

        # Check for internal IP disclosure
        for header, value in self.headers.items():
            ip_pattern = r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})'
            if re.search(ip_pattern, str(value)):
                self.findings.append({
                    'title': 'Internal IP Address Disclosure',
                    'description': f'Internal IP address found in {header} header',
                    'severity': 'MEDIUM',
                    'category': 'headers',
                    'cwe': 'CWE-200',
                    'remediation': 'Remove internal IP addresses from response headers',
                    'evidence': f'{header}: {value}'
                })

    def check_permissions_policy(self):
        """Check Permissions-Policy (formerly Feature-Policy) header."""
        pp = self.headers.get('Permissions-Policy', self.headers.get('Feature-Policy', ''))
        if not pp:
            self.findings.append({
                'title': 'Missing Permissions-Policy Header',
                'description': 'No Permissions-Policy header found — browser features unrestricted',
                'severity': 'LOW',
                'category': 'headers',
                'owasp': 'A05:2021',
                'remediation': 'Add Permissions-Policy to restrict camera, microphone, geolocation, etc.',
                'evidence': 'Permissions-Policy header absent'
            })

    def check_cache_control(self):
        """Check cache control headers for sensitive pages."""
        cache_control = self.headers.get('Cache-Control', '')
        pragma = self.headers.get('Pragma', '')

        if 'no-store' not in cache_control and 'no-cache' not in cache_control:
            self.findings.append({
                'title': 'Missing Cache-Control Restrictions',
                'description': 'Sensitive pages may be cached by proxies or browsers',
                'severity': 'LOW',
                'category': 'headers',
                'owasp': 'A05:2021',
                'cwe': 'CWE-525',
                'remediation': 'Add Cache-Control: no-store, no-cache, must-revalidate for sensitive pages',
                'evidence': f'Cache-Control: {cache_control or "(not set)"}'
            })
