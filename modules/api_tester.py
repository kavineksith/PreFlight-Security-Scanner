"""
OWASP API Top 10 Security Tester
Tests for API-specific vulnerabilities
"""

import time
import json
from urllib.parse import urljoin
from colorama import Fore, Style

class APITester:
    def __init__(self, session, api_base):
        self.session = session
        self.api_base = api_base.rstrip('/')
        self.findings = []
        
    def run_all_tests(self, is_authenticated):
        """Run all API security tests"""
        
        self.test_broken_object_level_auth()
        self.test_excessive_data_exposure()
        self.test_rate_limiting()
        self.test_broken_function_level_auth()
        self.test_ssrf_api()
        self.test_mass_assignment()
        self.test_injection_api()
        self.test_security_misconfigurations_api()
        
        return self.findings
    
    def test_broken_object_level_auth(self):
        """Test for BOLA (API1:2023)"""
        print(f"{Fore.YELLOW}[*] Testing API Broken Object Level Auth...{Style.RESET_ALL}")
        
        # Test patterns for IDOR in APIs
        test_patterns = [
            ('/user/1', 2),
            ('/users/1', 2),
            ('/profile?id=1', 2),
            ('/api/v1/orders/1', 2),
            ('/customers/1', 2)
        ]
        
        for pattern, test_id in test_patterns:
            url = urljoin(self.api_base, pattern)
            try:
                # Try to access with different ID
                test_url = url.replace('1', str(test_id))
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200 and len(response.text) > 50:
                    self.findings.append({
                        'title': 'Broken Object Level Authorization (BOLA)',
                        'description': f'Unauthorized access to other users\' resources at {test_url}',
                        'severity': 'HIGH',
                        'api_owasp': 'API1:2023',
                        'cwe': 'CWE-639',
                        'remediation': 'Implement user context validation for every object access',
                        'evidence': f'Successfully accessed resource ID {test_id} from authenticated session'
                    })
                    return
            except:
                continue
    
    def test_excessive_data_exposure(self):
        """Test for excessive data exposure (API3:2023)"""
        print(f"{Fore.YELLOW}[*] Testing excessive data exposure...{Style.RESET_ALL}")
        
        sensitive_fields = ['password', 'ssn', 'credit_card', 'token', 'secret', 'key', 'salt']
        
        try:
            response = self.session.get(urljoin(self.api_base, '/user/me'), timeout=5)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    exposed = [field for field in sensitive_fields if field in str(data).lower()]
                    
                    if exposed:
                        self.findings.append({
                            'title': 'Excessive Data Exposure',
                            'description': f'API returns sensitive fields: {", ".join(exposed)}',
                            'severity': 'MEDIUM',
                            'api_owasp': 'API3:2023',
                            'cwe': 'CWE-200',
                            'remediation': 'Implement proper response filtering, never return sensitive data',
                            'evidence': f'Fields {exposed} found in API response'
                        })
                except:
                    pass
        except:
            pass
    
    def test_rate_limiting(self):
        """Test for lack of rate limiting (API4:2023)"""
        print(f"{Fore.YELLOW}[*] Testing rate limiting...{Style.RESET_ALL}")
        
        test_endpoint = urljoin(self.api_base, '/login')
        start_time = time.time()
        success_count = 0
        
        # Send 50 rapid requests
        for i in range(50):
            try:
                response = self.session.post(test_endpoint, json={'test': i}, timeout=1)
                if response.status_code != 429:  # 429 = Too Many Requests
                    success_count += 1
            except:
                pass
        
        elapsed = time.time() - start_time
        
        if success_count > 40 and elapsed < 10:
            self.findings.append({
                'title': 'Lack of Rate Limiting',
                'description': f'Successfully sent {success_count} requests without rate limiting',
                'severity': 'MEDIUM',
                'api_owasp': 'API4:2023',
                'cwe': 'CWE-770',
                'remediation': 'Implement rate limiting (e.g., 100 requests per minute per user)',
                'evidence': f'{success_count}/50 requests succeeded without 429 responses'
            })
    
    def test_broken_function_level_auth(self):
        """Test for broken function level auth (API5:2023)"""
        print(f"{Fore.YELLOW}[*] Testing function level authorization...{Style.RESET_ALL}")
        
        admin_functions = [
            ('/admin/users', 'GET'),
            ('/admin/delete', 'DELETE'),
            ('/system/config', 'GET'),
            ('/debug/clear-cache', 'POST')
        ]
        
        for endpoint, method in admin_functions:
            url = urljoin(self.api_base, endpoint)
            try:
                if method == 'GET':
                    response = self.session.get(url, timeout=5)
                elif method == 'DELETE':
                    response = self.session.delete(url, timeout=5)
                else:
                    response = self.session.post(url, json={}, timeout=5)
                
                if response.status_code in [200, 201, 202, 204]:
                    self.findings.append({
                        'title': 'Broken Function Level Authorization',
                        'description': f'Admin function {method} {endpoint} accessible without admin role',
                        'severity': 'CRITICAL',
                        'api_owasp': 'API5:2023',
                        'cwe': 'CWE-285',
                        'remediation': 'Implement role-based access control for all API endpoints',
                        'evidence': f'Successfully accessed {endpoint} with status {response.status_code}'
                    })
                    return
            except:
                continue
    
    def test_ssrf_api(self):
        """Test for SSRF in APIs (API7:2023)"""
        print(f"{Fore.YELLOW}[*] Testing API SSRF...{Style.RESET_ALL}")
        
        ssrf_endpoints = ['/fetch', '/proxy', '/external', '/webhook']
        
        for endpoint in ssrf_endpoints:
            url = urljoin(self.api_base, endpoint)
            try:
                # Test with internal IP
                payload = {'url': 'http://169.254.169.254/latest/meta-data/', 'uri': 'http://localhost:80'}
                response = self.session.post(url, json=payload, timeout=5)
                
                if response.status_code == 200 and len(response.text) > 10:
                    self.findings.append({
                        'title': 'SSRF Vulnerability in API',
                        'description': f'API endpoint {endpoint} allows fetching internal resources',
                        'severity': 'HIGH',
                        'api_owasp': 'API7:2023',
                        'cwe': 'CWE-918',
                        'remediation': 'Validate and restrict URLs, use allowlists, block internal IPs',
                        'evidence': f'Successfully fetched internal resource via {endpoint}'
                    })
                    return
            except:
                continue
    
    def test_mass_assignment(self):
        """Test for mass assignment vulnerabilities"""
        print(f"{Fore.YELLOW}[*] Testing mass assignment...{Style.RESET_ALL}")
        
        update_endpoints = ['/user/update', '/profile', '/settings']
        
        for endpoint in update_endpoints:
            url = urljoin(self.api_base, endpoint)
            try:
                # Try to update protected fields
                payload = {
                    'username': 'test',
                    'email': 'test@test.com',
                    'is_admin': True,
                    'role': 'admin',
                    'password': 'hacked123'
                }
                
                response = self.session.put(url, json=payload, timeout=5)
                
                if response.status_code in [200, 201, 202]:
                    self.findings.append({
                        'title': 'Mass Assignment Vulnerability',
                        'description': f'API endpoint {endpoint} allows updating protected fields',
                        'severity': 'HIGH',
                        'cwe': 'CWE-915',
                        'remediation': 'Use allowlists for updatable fields, separate DTOs for different operations',
                        'evidence': f'Successfully sent update with admin role field'
                    })
                    return
            except:
                continue
    
    def test_injection_api(self):
        """Test for injection in APIs"""
        print(f"{Fore.YELLOW}[*] Testing API injection...{Style.RESET_ALL}")
        
        injection_payloads = [
            {"query": {"$ne": null}},
            {"username": {"$regex": ".*"}},
            {"search": "'; DROP TABLE users; --"},
            {"id": {"$gt": 0}}
        ]
        
        for payload in injection_payloads:
            try:
                response = self.session.post(urljoin(self.api_base, '/search'), json=payload, timeout=5)
                
                if response.status_code == 200 and ('error' not in response.text.lower() or 'exception' not in response.text.lower()):
                    self.findings.append({
                        'title': 'NoSQL/Injection in API',
                        'description': 'API may be vulnerable to NoSQL or SQL injection',
                        'severity': 'HIGH',
                        'api_owasp': 'API8:2023',
                        'cwe': 'CWE-943',
                        'remediation': 'Validate and sanitize all input, use parameterized queries',
                        'evidence': f'Payload {payload} accepted without error'
                    })
                    return
            except:
                continue
    
    def test_security_misconfigurations_api(self):
        """Test for API security misconfigurations"""
        print(f"{Fore.YELLOW}[*] Testing API security misconfigurations...{Style.RESET_ALL}")
        
        # Test CORS
        try:
            response = self.session.options(urljoin(self.api_base, '/'), 
                headers={'Origin': 'https://evil.com', 'Access-Control-Request-Method': 'GET'})
            
            if 'Access-Control-Allow-Origin: *' in str(response.headers) or 'Access-Control-Allow-Origin: https://evil.com' in str(response.headers):
                self.findings.append({
                    'title': 'API CORS Misconfiguration',
                    'description': 'CORS allows arbitrary origins',
                    'severity': 'MEDIUM',
                    'api_owasp': 'API8:2023',
                    'remediation': 'Restrict CORS to specific trusted origins',
                    'evidence': 'Access-Control-Allow-Origin: * detected'
                })
        except:
            pass
        
        # Test for version disclosure
        try:
            response = self.session.get(urljoin(self.api_base, '/'), timeout=5)
            headers = str(response.headers).lower()
            
            if 'server:' in headers or 'x-powered-by' in headers or 'version' in headers:
                self.findings.append({
                    'title': 'API Version/Stack Disclosure',
                    'description': 'API reveals server/version information in headers',
                    'severity': 'LOW',
                    'api_owasp': 'API8:2023',
                    'remediation': 'Remove or obscure identifying headers',
                    'evidence': 'Server version information exposed in response headers'
                })
        except:
            pass