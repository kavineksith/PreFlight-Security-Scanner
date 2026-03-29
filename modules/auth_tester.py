"""
Authentication & Authorization Testing Module
Tests: IDOR, privilege escalation, session management, JWT security
"""

import re
import json
import time
import jwt
import requests
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style

class AuthTester:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []
        
    def run_all_tests(self, is_authenticated, username=None, password=None):
        """Run all authentication and authorization tests"""
        
        # Authentication tests
        if not is_authenticated:
            self.test_default_credentials()
            self.test_weak_password_policy()
            self.test_account_lockout()
        
        # Session management tests
        self.test_session_fixation()
        self.test_session_timeout()
        self.test_cookie_security()
        
        # JWT tests (if applicable)
        self.test_jwt_security()
        
        # Authorization tests (requires authentication)
        if is_authenticated:
            self.test_idor_vulnerabilities()
            self.test_privilege_escalation()
            self.test_horizontal_access_control()
            self.test_functional_access_control()
        
        return self.findings
    
    def test_default_credentials(self):
        """Test for default or weak credentials"""
        print(f"{Fore.YELLOW}[*] Testing default credentials...{Style.RESET_ALL}")
        
        default_pairs = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
            ('test', 'test'), ('root', 'root'), ('user', 'user'),
            ('administrator', 'administrator'), ('admin', 'password123')
        ]
        
        for username, password in default_pairs:
            try:
                response = self.session.post(
                    urljoin(self.base_url, '/login'),
                    data={'username': username, 'password': password},
                    timeout=5,
                    allow_redirects=False
                )
                
                if response.status_code == 302 or 'dashboard' in response.text.lower():
                    self.findings.append({
                        'title': 'Default Credentials Detected',
                        'description': f'Default credentials {username}:{password} allow authentication',
                        'severity': 'CRITICAL',
                        'owasp': 'A07:2021',
                        'cwe': 'CWE-798',
                        'remediation': 'Remove default accounts and enforce strong password policies',
                        'evidence': f'Successful login with {username}:{password}'
                    })
                    break
            except:
                continue
    
    def test_idor_vulnerabilities(self):
        """Test for Insecure Direct Object References (IDOR)"""
        print(f"{Fore.YELLOW}[*] Testing IDOR vulnerabilities...{Style.RESET_ALL}")
        
        # Common IDOR patterns
        idor_endpoints = [
            '/api/user/{id}', '/api/profile?id={id}', '/api/order/{id}',
            '/api/invoice/{id}', '/user/{id}/profile', '/api/messages?user_id={id}'
        ]
        
        # Test numeric ID traversal
        for pattern in idor_endpoints:
            for test_id in [1, 2, 3, 999, 'admin', '../admin']:
                endpoint = pattern.format(id=test_id)
                url = urljoin(self.base_url, endpoint)
                
                try:
                    response = self.session.get(url, timeout=5)
                    
                    # Check for data leakage of other users
                    if response.status_code == 200 and len(response.text) > 50:
                        if any(keyword in response.text.lower() for keyword in 
                               ['password', 'email', 'ssn', 'credit', 'address', 'phone']):
                            self.findings.append({
                                'title': 'IDOR Vulnerability Detected',
                                'description': f'Unauthorized access to {url} with ID {test_id}',
                                'severity': 'HIGH',
                                'owasp': 'A01:2021',
                                'api_owasp': 'API1:2023',
                                'cwe': 'CWE-639',
                                'remediation': 'Implement server-side access control checks for all object references',
                                'evidence': f'Accessed {endpoint} with ID {test_id} and received sensitive data'
                            })
                            return
                except:
                    continue
    
    def test_privilege_escalation(self):
        """Test for vertical privilege escalation"""
        print(f"{Fore.YELLOW}[*] Testing privilege escalation...{Style.RESET_ALL}")
        
        admin_endpoints = [
            '/admin', '/administrator', '/admin/users', '/admin/settings',
            '/api/admin', '/api/users/delete', '/api/system/config'
        ]
        
        for endpoint in admin_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            try:
                # Try GET request
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    self.findings.append({
                        'title': 'Privilege Escalation',
                        'description': f'Admin endpoint {endpoint} accessible without admin privileges',
                        'severity': 'CRITICAL',
                        'owasp': 'A01:2021',
                        'cwe': 'CWE-269',
                        'remediation': 'Implement role-based access control (RBAC) and validate permissions on every request',
                        'evidence': f'Successfully accessed {endpoint} with status {response.status_code}'
                    })
                    return
            except:
                continue
    
    def test_horizontal_access_control(self):
        """Test for horizontal privilege escalation (same role, different user)"""
        print(f"{Fore.YELLOW}[*] Testing horizontal access control...{Style.RESET_ALL}")
        
        # Try to access profile of different user IDs
        for user_id in [2, 3, 5, 10]:
            endpoints = [
                f'/api/user/{user_id}',
                f'/user/{user_id}/profile',
                f'/profile?uid={user_id}'
            ]
            
            for endpoint in endpoints:
                url = urljoin(self.base_url, endpoint)
                try:
                    response = self.session.get(url, timeout=5)
                    
                    if response.status_code == 200 and user_id != 1:
                        if 'email' in response.text.lower() or 'username' in response.text.lower():
                            self.findings.append({
                                'title': 'Horizontal Privilege Escalation',
                                'description': f'Accessing other user\'s data at {endpoint}',
                                'severity': 'HIGH',
                                'owasp': 'A01:2021',
                                'cwe': 'CWE-639',
                                'remediation': 'Verify user identity and ownership for all data access',
                                'evidence': f'Accessed user {user_id} data from authenticated session'
                            })
                            return
                except:
                    continue
    
    def test_functional_access_control(self):
        """Test for missing function-level access control"""
        print(f"{Fore.YELLOW}[*] Testing functional access control...{Style.RESET_ALL}")
        
        sensitive_actions = [
            ('/api/user/delete/1', 'DELETE'),
            ('/api/user/create', 'POST'),
            ('/admin/delete_all_users', 'GET'),
            ('/api/settings/update', 'PUT'),
            ('/api/database/query', 'POST')
        ]
        
        for endpoint, method in sensitive_actions:
            url = urljoin(self.base_url, endpoint)
            try:
                if method == 'GET':
                    response = self.session.get(url, timeout=5)
                elif method == 'DELETE':
                    response = self.session.delete(url, timeout=5)
                elif method == 'POST':
                    response = self.session.post(url, json={}, timeout=5)
                else:
                    response = self.session.put(url, json={}, timeout=5)
                
                if response.status_code in [200, 201, 202, 204]:
                    self.findings.append({
                        'title': 'Missing Function-Level Access Control',
                        'description': f'Sensitive action {method} {endpoint} accessible',
                        'severity': 'CRITICAL',
                        'owasp': 'A01:2021',
                        'cwe': 'CWE-285',
                        'remediation': 'Implement access control checks for every business function',
                        'evidence': f'Successfully performed {method} on {endpoint}'
                    })
                    return
            except:
                continue
    
    def test_session_fixation(self):
        """Test for session fixation vulnerability"""
        print(f"{Fore.YELLOW}[*] Testing session fixation...{Style.RESET_ALL}")
        
        try:
            # Get session before login
            initial_session = self.session.cookies.get_dict()
            self.session.get(self.base_url, timeout=5)
            
            # After login attempt, check if session ID changed
            if hasattr(self, 'username') and self.username:
                self.session.post(urljoin(self.base_url, '/login'),
                                 data={'username': self.username, 'password': 'wrong'},
                                 timeout=5)
                
                new_session = self.session.cookies.get_dict()
                
                if initial_session == new_session:
                    self.findings.append({
                        'title': 'Session Fixation Vulnerability',
                        'description': 'Session ID remains unchanged before and after authentication attempt',
                        'severity': 'MEDIUM',
                        'owasp': 'A07:2021',
                        'cwe': 'CWE-384',
                        'remediation': 'Regenerate session ID after successful authentication',
                        'evidence': f'Session ID unchanged after login attempt'
                    })
        except:
            pass
    
    def test_session_timeout(self):
        """Test for session timeout configuration"""
        print(f"{Fore.YELLOW}[*] Testing session timeout...{Style.RESET_ALL}")
        
        # This is a simplified test - real test would require longer wait
        self.findings.append({
            'title': 'Session Timeout Review Required',
            'description': 'Manually verify session timeout is set to 30 minutes or less',
            'severity': 'MEDIUM',
            'owasp': 'A07:2021',
            'remediation': 'Implement session timeout of 30 minutes maximum',
            'evidence': 'Automated check requires manual verification'
        })
    
    def test_cookie_security(self):
        """Test for secure cookie attributes"""
        print(f"{Fore.YELLOW}[*] Testing cookie security...{Style.RESET_ALL}")
        
        cookies = self.session.cookies.get_dict()
        if cookies:
            # This is a simplified test
            self.findings.append({
                'title': 'Cookie Security Review',
                'description': 'Ensure cookies have HttpOnly, Secure, and SameSite attributes',
                'severity': 'MEDIUM',
                'owasp': 'A05:2021',
                'remediation': 'Set Secure, HttpOnly, and SameSite=Strict flags on all cookies',
                'evidence': f'Found {len(cookies)} cookies without verification of security flags'
            })
    
    def test_jwt_security(self):
        """Test JWT token security"""
        print(f"{Fore.YELLOW}[*] Testing JWT security...{Style.RESET_ALL}")
        
        # Look for JWT in requests
        for cookie in self.session.cookies:
            if 'token' in cookie.name.lower() or 'jwt' in cookie.name.lower():
                try:
                    # Try to decode without verification
                    decoded = jwt.decode(cookie.value, options={"verify_signature": False})
                    self.findings.append({
                        'title': 'JWT Security Issues',
                        'description': 'JWT token found - verify algorithm, expiration, and signature validation',
                        'severity': 'HIGH',
                        'owasp': 'A07:2021',
                        'remediation': 'Use strong algorithms (RS256/ES256), set short expiration, validate signature',
                        'evidence': f'JWT decoded payload: {decoded}'
                    })
                except:
                    pass
    
    def test_weak_password_policy(self):
        """Test for weak password policy enforcement"""
        print(f"{Fore.YELLOW}[*] Testing password policy...{Style.RESET_ALL}")
        
        weak_passwords = ['123456', 'password', 'qwerty', 'admin123', 'test']
        
        for weak_pass in weak_passwords:
            try:
                response = self.session.post(
                    urljoin(self.base_url, '/register'),
                    data={'username': 'testuser', 'password': weak_pass, 'email': 'test@test.com'},
                    timeout=5
                )
                
                if response.status_code == 200 and 'success' in response.text.lower():
                    self.findings.append({
                        'title': 'Weak Password Policy',
                        'description': f'Weak password "{weak_pass}" accepted during registration',
                        'severity': 'MEDIUM',
                        'owasp': 'A07:2021',
                        'cwe': 'CWE-521',
                        'remediation': 'Enforce password complexity (length, characters, numbers, symbols)',
                        'evidence': f'Registration successful with password: {weak_pass}'
                    })
                    return
            except:
                continue
    
    def test_account_lockout(self):
        """Test for account lockout mechanism"""
        print(f"{Fore.YELLOW}[*] Testing account lockout...{Style.RESET_ALL}")
        
        # This would require multiple failed attempts
        # Simplified check
        self.findings.append({
            'title': 'Account Lockout Review',
            'description': 'Verify account locks after 5 failed login attempts',
            'severity': 'MEDIUM',
            'owasp': 'A07:2021',
            'remediation': 'Implement account lockout after 5 failed attempts',
            'evidence': 'Manual verification required for lockout mechanism'
        })