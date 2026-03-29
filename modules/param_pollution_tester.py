"""
Parameter Pollution & Mass Assignment Tester
Tests HPP, mass assignment, hidden params, and type juggling.
"""

import json
from urllib.parse import urljoin, urlencode
from colorama import Fore, Style


class ParamPollutionTester:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []

    def run_all_checks(self):
        print(f"{Fore.CYAN}[*] Parameter Pollution & Mass Assignment Testing{Style.RESET_ALL}")
        self.test_http_param_pollution()
        self.test_mass_assignment()
        self.test_hidden_params()
        self.test_type_juggling()
        self.test_parameter_tampering()
        return self.findings

    def test_http_param_pollution(self):
        print(f"{Fore.YELLOW}[*] Testing HTTP parameter pollution...{Style.RESET_ALL}")
        test_endpoints = ['/search', '/api/search', '/login', '/api/users']
        for ep in test_endpoints:
            url = urljoin(self.base_url, ep)
            try:
                # Send duplicate params
                r = self.session.get(f"{url}?q=normal&q=injected", timeout=5)
                if r.status_code == 200 and 'injected' in r.text:
                    self.findings.append({
                        'title': 'HTTP Parameter Pollution (HPP)',
                        'description': f'Duplicate parameters processed at {ep}',
                        'severity': 'MEDIUM', 'category': 'param_pollution',
                        'owasp': 'A03:2021', 'cwe': 'CWE-235',
                        'remediation': 'Process only the first occurrence of duplicate parameters',
                        'evidence': f'q=normal&q=injected — "injected" used at {ep}'
                    })
                    return
            except Exception:
                continue

    def test_mass_assignment(self):
        print(f"{Fore.YELLOW}[*] Testing mass assignment...{Style.RESET_ALL}")
        priv_fields = [
            {'is_admin': True, 'role': 'admin'},
            {'privilege': 'superuser', 'access_level': 999},
            {'admin': True, 'staff': True, 'verified': True},
            {'account_type': 'premium', 'balance': 999999},
        ]
        endpoints = ['/api/user/update', '/api/profile', '/api/settings',
                     '/api/me', '/api/account', '/profile', '/settings']
        for ep in endpoints:
            url = urljoin(self.base_url, ep)
            for fields in priv_fields:
                try:
                    base_data = {'username': 'test', 'email': 'test@test.com'}
                    base_data.update(fields)
                    r = self.session.put(url, json=base_data, timeout=5)
                    if r.status_code in (200, 201, 202):
                        self.findings.append({
                            'title': 'Mass Assignment Vulnerability',
                            'description': f'Privileged fields accepted at {ep}: {list(fields.keys())}',
                            'severity': 'HIGH', 'category': 'param_pollution',
                            'owasp': 'A01:2021', 'cwe': 'CWE-915',
                            'remediation': 'Use allowlists for updatable fields, separate DTOs for operations',
                            'evidence': f'PUT {ep} with {list(fields.keys())} returned {r.status_code}',
                            'mitre_attack': 'T1098'
                        })
                        return
                except Exception:
                    continue

    def test_hidden_params(self):
        print(f"{Fore.YELLOW}[*] Testing hidden parameter discovery...{Style.RESET_ALL}")
        hidden_params = ['debug', 'test', 'admin', 'internal', 'verbose',
                         'dev', 'staging', 'trace', 'config', 'secret']
        for param in hidden_params:
            for val in ['true', '1', 'yes', 'on']:
                try:
                    url = f"{self.base_url}?{param}={val}"
                    r = self.session.get(url, timeout=5)
                    if r.status_code == 200:
                        if any(k in r.text.lower() for k in ['debug', 'stack', 'trace', 'config', 'environment']):
                            self.findings.append({
                                'title': f'Hidden Parameter Accepted: {param}',
                                'description': f'Parameter "{param}={val}" enables debug/internal mode',
                                'severity': 'MEDIUM', 'category': 'param_pollution',
                                'owasp': 'A05:2021', 'cwe': 'CWE-489',
                                'remediation': 'Remove debug/test parameters in production',
                                'evidence': f'?{param}={val} changed response behavior'
                            })
                            return
                except Exception:
                    continue

    def test_type_juggling(self):
        print(f"{Fore.YELLOW}[*] Testing type juggling...{Style.RESET_ALL}")
        payloads = [
            {'password': True},
            {'password': 0},
            {'password': []},
            {'password': None},
            {'password': {'$gt': ''}},
        ]
        login_url = urljoin(self.base_url, '/api/login')
        for payload in payloads:
            data = {'username': 'admin'}
            data.update(payload)
            try:
                r = self.session.post(login_url, json=data, timeout=5)
                if r.status_code == 200 and any(k in r.text.lower() for k in ['token', 'success', 'session']):
                    self.findings.append({
                        'title': 'Type Juggling Authentication Bypass',
                        'description': f'Non-string password type accepted: {type(payload["password"]).__name__}',
                        'severity': 'CRITICAL', 'category': 'param_pollution',
                        'cwe': 'CWE-843',
                        'remediation': 'Enforce strict type checking on all input parameters',
                        'evidence': f'password={payload["password"]} (type: {type(payload["password"]).__name__}) accepted'
                    })
                    return
            except Exception:
                continue

    def test_parameter_tampering(self):
        print(f"{Fore.YELLOW}[*] Testing parameter tampering...{Style.RESET_ALL}")
        tampering_tests = [
            ('/api/order', {'price': 0, 'quantity': 1}),
            ('/api/order', {'price': -1, 'quantity': 1}),
            ('/api/transfer', {'amount': -100}),
            ('/api/checkout', {'discount': 100}),
        ]
        for ep, data in tampering_tests:
            url = urljoin(self.base_url, ep)
            try:
                r = self.session.post(url, json=data, timeout=5)
                if r.status_code in (200, 201):
                    self.findings.append({
                        'title': 'Parameter Tampering Accepted',
                        'description': f'Abnormal values accepted at {ep}: {data}',
                        'severity': 'HIGH', 'category': 'param_pollution',
                        'cwe': 'CWE-20',
                        'remediation': 'Validate parameter ranges server-side (no negative prices/amounts)',
                        'evidence': f'POST {ep} with {data} returned {r.status_code}'
                    })
                    return
            except Exception:
                continue
