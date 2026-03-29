"""
OWASP Top 10 Vulnerability Scanner
Tests for common web vulnerabilities
"""

import re
import time
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style

class OWASPScanner:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []
        
    def run_all_checks(self, is_authenticated):
        """Run all OWASP Top 10 checks"""
        
        self.test_sql_injection()
        self.test_xss_vulnerabilities()
        self.test_command_injection()
        self.test_path_traversal()
        self.test_security_misconfigurations()
        self.test_csrf_vulnerabilities()
        self.test_ssrf_vulnerabilities()
        self.test_file_upload_vulnerabilities()
        
        return self.findings
    
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Testing SQL injection...{Style.RESET_ALL}")
        
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL--",
            "admin' --",
            "' OR '1'='1' /*"
        ]
        
        # Common vulnerable parameters
        test_params = ['id', 'user', 'q', 'search', 'username', 'email']
        
        for param in test_params:
            for payload in sql_payloads:
                test_url = f"{self.base_url}/search?{param}={payload}"
                try:
                    response = self.session.get(test_url, timeout=5)
                    
                    # Look for SQL error messages
                    sql_errors = [
                        'sql syntax', 'mysql_fetch', 'ora-', 'postgresql error',
                        'sqlite3', 'microsoft jet database', 'odbc driver'
                    ]
                    
                    if any(error in response.text.lower() for error in sql_errors):
                        self.findings.append({
                            'title': 'SQL Injection Vulnerability',
                            'description': f'SQL injection possible in parameter: {param}',
                            'severity': 'CRITICAL',
                            'owasp': 'A03:2021',
                            'cwe': 'CWE-89',
                            'remediation': 'Use parameterized queries/prepared statements, validate all input',
                            'evidence': f'Payload "{payload}" triggered SQL error in {param}'
                        })
                        return
                except:
                    continue
    
    def test_xss_vulnerabilities(self):
        """Test for Cross-Site Scripting (XSS) vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Testing XSS vulnerabilities...{Style.RESET_ALL}")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "'><script>alert(1)</script>",
            "\"><script>alert(1)</script>"
        ]
        
        test_params = ['q', 'search', 'name', 'comment', 'message']
        
        for param in test_params:
            for payload in xss_payloads:
                test_url = f"{self.base_url}/search?{param}={payload}"
                try:
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check if payload is reflected unescaped
                    if payload in response.text and '<' in response.text:
                        self.findings.append({
                            'title': 'Cross-Site Scripting (XSS)',
                            'description': f'XSS vulnerability in parameter: {param}',
                            'severity': 'HIGH',
                            'owasp': 'A03:2021',
                            'cwe': 'CWE-79',
                            'remediation': 'Proper output encoding, Content Security Policy, input validation',
                            'evidence': f'Payload "{payload}" reflected in response'
                        })
                        return
                except:
                    continue
    
    def test_command_injection(self):
        """Test for command injection vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Testing command injection...{Style.RESET_ALL}")
        
        cmd_payloads = [
            '; ls',
            '| dir',
            '|| cat /etc/passwd',
            '`id`',
            '$(whoami)'
        ]
        
        test_params = ['ping', 'host', 'ip', 'domain', 'file']
        
        for param in test_params:
            for payload in cmd_payloads:
                test_url = f"{self.base_url}/tools?{param}={payload}"
                try:
                    response = self.session.get(test_url, timeout=5)
                    
                    # Look for command output indicators
                    cmd_indicators = ['root:', 'uid=', 'Directory of', 'etc/passwd']
                    
                    if any(indicator in response.text.lower() for indicator in cmd_indicators):
                        self.findings.append({
                            'title': 'Command Injection Vulnerability',
                            'description': f'Command injection possible in parameter: {param}',
                            'severity': 'CRITICAL',
                            'owasp': 'A03:2021',
                            'cwe': 'CWE-78',
                            'remediation': 'Avoid system calls with user input, use allowlists, sanitize input',
                            'evidence': f'Command "{payload}" executed successfully'
                        })
                        return
                except:
                    continue
    
    def test_path_traversal(self):
        """Test for path traversal vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Testing path traversal...{Style.RESET_ALL}")
        
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ]
        
        test_params = ['file', 'path', 'doc', 'template', 'page']
        
        for param in test_params:
            for payload in traversal_payloads:
                test_url = f"{self.base_url}/download?{param}={payload}"
                try:
                    response = self.session.get(test_url, timeout=5)
                    
                    if 'root:' in response.text or '[extensions]' in response.text:
                        self.findings.append({
                            'title': 'Path Traversal Vulnerability',
                            'description': f'Path traversal possible in parameter: {param}',
                            'severity': 'HIGH',
                            'owasp': 'A01:2021',
                            'cwe': 'CWE-22',
                            'remediation': 'Use allowlist of permitted files, validate path canonicalization',
                            'evidence': f'Successfully read file using {payload}'
                        })
                        return
                except:
                    continue
    
    def test_security_misconfigurations(self):
        """Test for security misconfigurations"""
        print(f"{Fore.YELLOW}[*] Testing security misconfigurations...{Style.RESET_ALL}")
        
        # Test for directory listing
        try:
            response = self.session.get(urljoin(self.base_url, '/uploads/'), timeout=5)
            if 'Index of /' in response.text or 'Parent Directory' in response.text:
                self.findings.append({
                    'title': 'Directory Listing Enabled',
                    'description': 'Directory listing enabled on /uploads/',
                    'severity': 'MEDIUM',
                    'owasp': 'A05:2021',
                    'cwe': 'CWE-548',
                    'remediation': 'Disable directory listing in web server configuration',
                    'evidence': 'Directory listing showing file structure'
                })
        except:
            pass
        
        # Test for debug information
        debug_endpoints = ['/debug', '/_debug', '/status', '/info', '/health']
        for endpoint in debug_endpoints:
            try:
                response = self.session.get(urljoin(self.base_url, endpoint), timeout=5)
                if response.status_code == 200 and ('debug' in response.text.lower() or 'traceback' in response.text.lower()):
                    self.findings.append({
                        'title': 'Debug Information Exposed',
                        'description': f'Debug endpoint {endpoint} accessible',
                        'severity': 'HIGH',
                        'owasp': 'A05:2021',
                        'remediation': 'Disable debug mode in production',
                        'evidence': f'Debug information found at {endpoint}'
                    })
                    break
            except:
                continue
    
    def test_csrf_vulnerabilities(self):
        """Test for CSRF vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Testing CSRF protection...{Style.RESET_ALL}")
        
        # Look for forms without CSRF tokens
        try:
            response = self.session.get(urljoin(self.base_url, '/profile'), timeout=5)
            
            if 'csrf' not in response.text.lower() and 'token' not in response.text.lower():
                self.findings.append({
                    'title': 'Missing CSRF Protection',
                    'description': 'Forms detected without CSRF tokens',
                    'severity': 'MEDIUM',
                    'owasp': 'A01:2021',
                    'cwe': 'CWE-352',
                    'remediation': 'Implement anti-CSRF tokens for all state-changing operations',
                    'evidence': 'Forms found without CSRF protection'
                })
        except:
            pass
    
    def test_ssrf_vulnerabilities(self):
        """Test for Server-Side Request Forgery (SSRF)"""
        print(f"{Fore.YELLOW}[*] Testing SSRF vulnerabilities...{Style.RESET_ALL}")
        
        ssrf_endpoints = ['/fetch', '/proxy', '/webhook', '/api/external', '/load']
        
        for endpoint in ssrf_endpoints:
            try:
                # Test with internal address
                data = {'url': 'http://localhost:80/admin', 'uri': 'http://127.0.0.1:80'}
                response = self.session.post(urljoin(self.base_url, endpoint), json=data, timeout=5)
                
                if response.status_code == 200 and ('admin' in response.text.lower() or 'localhost' in response.text.lower()):
                    self.findings.append({
                        'title': 'SSRF Vulnerability',
                        'description': f'SSRF possible at {endpoint}',
                        'severity': 'HIGH',
                        'owasp': 'A10:2021',
                        'api_owasp': 'API7:2023',
                        'cwe': 'CWE-918',
                        'remediation': 'Validate and restrict URL schemes, implement allowlist of domains',
                        'evidence': f'Successfully accessed internal resource via {endpoint}'
                    })
                    break
            except:
                continue
    
    def test_file_upload_vulnerabilities(self):
        """Test for insecure file upload functionality"""
        print(f"{Fore.YELLOW}[*] Testing file upload security...{Style.RESET_ALL}")
        
        upload_endpoints = ['/upload', '/api/upload', '/file/upload']
        
        malicious_files = [
            ('test.php', '<?php phpinfo(); ?>', 'application/x-php'),
            ('test.jsp', '<% out.println("test"); %>', 'text/plain'),
            ('test.html', '<script>alert(1)</script>', 'text/html')
        ]
        
        for endpoint in upload_endpoints:
            for filename, content, mime in malicious_files:
                try:
                    files = {'file': (filename, content, mime)}
                    response = self.session.post(urljoin(self.base_url, endpoint), files=files, timeout=5)
                    
                    if response.status_code in [200, 201, 202]:
                        self.findings.append({
                            'title': 'Insecure File Upload',
                            'description': f'Executable file {filename} uploaded successfully to {endpoint}',
                            'severity': 'HIGH',
                            'owasp': 'A05:2021',
                            'cwe': 'CWE-434',
                            'remediation': 'Validate file type, scan for malware, rename files, store outside webroot',
                            'evidence': f'Uploaded {filename} without validation'
                        })
                        return
                except:
                    continue