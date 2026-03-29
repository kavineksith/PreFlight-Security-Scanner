"""
Security Headers Bypass Tester
Tests if restricted endpoints bypass access controls via HTTP headers (WAF Evasion/IP Spoofing)
"""

import concurrent.futures
from urllib.parse import urljoin
from colorama import Fore, Style

class HeaderBypassTester:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []
        
        # Comprehensive list of headers used to spoof IP addresses or circumvent WAFs/Proxies
        self.bypass_headers = {
            'X-Forwarded-For': '127.0.0.1',
            'X-Forwarded-Host': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Remote-Addr': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'X-Host': '127.0.0.1',
            'X-Custom-IP-Authorization': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'True-Client-IP': '127.0.0.1',
            'Client-IP': '127.0.0.1',
            'X-ProxyUser-Ip': '127.0.0.1',
            'X-Wap-Profile': '127.0.0.1',
            'Forwarded': 'for=127.0.0.1;by=127.0.0.1;host=127.0.0.1',
            'Contact': 'root@localhost',
            'X-Original-URL': '/admin',
            'X-Rewrite-URL': '/admin',
            'X-Override-URL': '/admin'
        }
        
    def run_all_checks(self):
        """Run all security header evasions."""
        print(f"{Fore.CYAN}[*] Security Headers Access Bypassing{Style.RESET_ALL}")
        
        self.test_ip_spoofing_bypass()
        self.test_http_method_override()
        
        return self.findings

    def test_ip_spoofing_bypass(self):
        """Test if IP spoofing headers allow access to restricted administrative endpoints."""
        print(f"{Fore.YELLOW}[*] Testing WAF/Proxy IP Spoofing restrictions...{Style.RESET_ALL}")
        
        restricted_endpoints = ['/admin', '/server-status', '/config', '/api/admin', '/management']
        
        for endpoint in restricted_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            # Step 1: Establish a baseline response (should be 401 or 403 Forbidden usually)
            try:
                baseline_resp = self.session.get(url, timeout=5)
                # If it's 200 by default, it's not restricted, we skip to save time
                if baseline_resp.status_code == 200:
                    continue
            except Exception:
                continue

            def test_header(header_name, header_val):
                headers = {header_name: header_val}
                try:
                    resp = self.session.get(url, headers=headers, timeout=5)
                    # If we bypassed a 403 to get a 200 using the header
                    if resp.status_code == 200 and baseline_resp.status_code in [401, 403]:
                        self.findings.append({
                            'title': 'IP Spoofing / WAF Access Bypass',
                            'description': f'Access bypassed for {endpoint} using {header_name}',
                            'severity': 'CRITICAL',
                            'owasp': 'A01:2021',
                            'cwe': 'CWE-284',
                            'remediation': 'Do not rely entirely on X-Forwarded-For or proxy headers for access control decisions. Ensure the perimeter reverse-proxy strictly sets or sanitizes these headers.',
                            'evidence': f'Baseline returned {baseline_resp.status_code}. Request with {header_name}: {header_val} returned 200 OK.',
                            'mitre_attack': 'T1190'
                        })
                except Exception:
                    pass

            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                for h_name, h_val in self.bypass_headers.items():
                    executor.submit(test_header, h_name, h_val)

    def test_http_method_override(self):
        """Test for HTTP verb tunneling / Method Overriding to bypass WAF rules."""
        print(f"{Fore.YELLOW}[*] Testing HTTP Method Overriding Headers...{Style.RESET_ALL}")
        
        url = urljoin(self.base_url, '/api/admin/delete_all')
        
        override_headers = [
            {'X-HTTP-Method-Override': 'DELETE'},
            {'X-HTTP-Method': 'DELETE'},
            {'X-Method-Override': 'DELETE'}
        ]
        
        def test_override(headers):
            try:
                # We send a harmless GET but try to override it to DELETE implicitly
                resp = self.session.post(url, headers=headers, json={"test":"1"}, timeout=5)
                # If instead of a "Method Not Allowed" (405) we get a 200, the override succeeded
                if resp.status_code == 200:
                    header_name = list(headers.keys())[0]
                    self.findings.append({
                        'title': 'HTTP Method Override Vulnerability',
                        'description': f'WAF/Access control bypassed via {header_name}',
                        'severity': 'HIGH',
                        'api_owasp': 'API6:2023',
                        'cwe': 'CWE-650',
                        'remediation': 'Disable support for X-HTTP-Method-Override on backend APIs to prevent verb tunneling attacks.',
                        'evidence': f'POST request overridden to DELETE using {header_name}',
                        'mitre_attack': 'T1190'
                    })
            except Exception:
                pass
                
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            for h in override_headers:
                executor.submit(test_override, h)
