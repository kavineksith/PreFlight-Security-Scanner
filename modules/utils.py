"""
Utility functions for the scanner
"""

import re
import ssl
import socket
from urllib.parse import urlparse, urljoin
import requests
from colorama import Fore, Style

class Utils:
    def validate_url(self, url):
        """Validate URL format and accessibility"""
        try:
            result = urlparse(url)
            if all([result.scheme, result.netloc]):
                response = requests.head(url, timeout=5, verify=False)
                if response.status_code < 500:
                    return True
            return False
        except:
            return False
    
    def check_security_headers(self, url):
        """Check for security headers"""
        findings = []
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing CSP header',
                'X-Frame-Options': 'Missing X-Frame-Options (clickjacking risk)',
                'X-Content-Type-Options': 'Missing nosniff header',
                'Referrer-Policy': 'Missing referrer policy'
            }
            
            for header, message in security_headers.items():
                if header not in headers:
                    findings.append({
                        'title': f'Missing Security Header: {header}',
                        'description': message,
                        'severity': 'MEDIUM',
                        'owasp': 'A05:2021',
                        'remediation': f'Add {header} header with appropriate values',
                        'evidence': f'Header {header} not found in response'
                    })
        except:
            pass
        
        return findings
    
    def check_tls_security(self, url):
        """Check TLS/SSL configuration"""
        findings = []
        
        try:
            hostname = urlparse(url).hostname
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    if cert:
                        findings.append({
                            'title': 'TLS Certificate Check',
                            'description': 'Certificate found - verify expiration and validity',
                            'severity': 'LOW',
                            'remediation': 'Ensure certificate is valid and not expired',
                            'evidence': f'Certificate for {hostname} found'
                        })
        except:
            findings.append({
                'title': 'TLS Configuration Issue',
                'description': 'Unable to verify TLS configuration',
                'severity': 'MEDIUM',
                'remediation': 'Ensure HTTPS is properly configured',
                'evidence': 'TLS connection test failed'
            })
        
        return findings
    
    def check_sensitive_files(self, url):
        """Check for exposed sensitive files"""
        findings = []
        
        sensitive_paths = [
            '/.git/HEAD',
            '/.env',
            '/config.json',
            '/wp-config.php',
            '/backup.zip',
            '/database.sql',
            '/.htaccess',
            '/robots.txt',
            '/sitemap.xml'
        ]
        
        for path in sensitive_paths:
            try:
                test_url = urljoin(url, path)
                response = requests.get(test_url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    findings.append({
                        'title': f'Sensitive File Exposed: {path}',
                        'description': f'File {path} is publicly accessible',
                        'severity': 'HIGH',
                        'owasp': 'A05:2021',
                        'remediation': 'Restrict access to sensitive files via web server configuration',
                        'evidence': f'Successfully accessed {test_url}'
                    })
            except:
                continue
        
        return findings
    
    def check_error_handling(self, url, session):
        """Check for verbose error messages"""
        findings = []
        
        error_triggers = [
            ('/nonexistent', '404 error page'),
            ('/api/test?invalid=<>', 'Invalid input handling'),
            ('/api/test?large=' + 'A'*10000, 'Oversize input')
        ]
        
        for path, description in error_triggers:
            try:
                response = session.get(urljoin(url, path), timeout=5)
                
                # Check for stack traces or verbose errors
                error_indicators = ['traceback', 'exception', 'stack trace', 'sql', 'mysql', 'warning']
                
                if any(indicator in response.text.lower() for indicator in error_indicators):
                    findings.append({
                        'title': 'Verbose Error Message Disclosure',
                        'description': f'Error at {path} reveals internal information',
                        'severity': 'MEDIUM',
                        'owasp': 'A05:2021',
                        'remediation': 'Implement custom error pages, never show stack traces to users',
                        'evidence': f'Internal error details exposed at {path}'
                    })
                    break
            except:
                continue
        
        return findings