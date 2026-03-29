"""
Path/URI Bypass Tester
Tests for 403 Forbidden / Access Denied evasions via URI normalization, 
unicode bypasses, trailing slashes, and path traversal tactics against proxies/WAFs.
"""

import concurrent.futures
from urllib.parse import urljoin
from colorama import Fore, Style

class PathBypassTester:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []
        
        # Test paths commonly restricted
        self.target_paths = ['/admin', '/api/v1/users', '/server-status', '/config']

    def run_all_checks(self):
        """Run advanced path-based access control bypasses."""
        print(f"{Fore.CYAN}[*] Advanced URI Normalization & 403 Bypassing{Style.RESET_ALL}")
        
        self.test_path_normalization()
        
        return self.findings

    def test_path_normalization(self):
        """Test proxy/WAF parsing differences via path normalization tricks."""
        print(f"{Fore.YELLOW}[*] Testing 403 Forbidden URI bypasses...{Style.RESET_ALL}")
        
        for path in self.target_paths:
            url = urljoin(self.base_url, path)
            
            # Get baseline
            try:
                baseline_resp = self.session.get(url, timeout=3, allow_redirects=False)
                # We only test bypasses if the endpoint is actually protected (403 or 401)
                if baseline_resp.status_code not in [403, 401]:
                    continue
            except Exception:
                continue

            # Strip leading slash for mutation building
            p = path.lstrip('/')
            
            # WAF/Proxy evasion techniques
            mutations = [
                f"/{p}/", f"//{p}//", f"/./{p}/.", f"/%2e/{p}", f"/{p}/.", 
                f"//;//{p}", f"/.random/../{p}", f"/%20{p}%20/", f"/%09{p}",
                f"/{p}.json", f"/{p}.html", f"/{p}?", f"/{p}#", f"/*/{p}",
                f"/%2f{p}", f"/{p}%00", f"/{p.upper()}", f"/a/../{p}"
            ]
            
            def check_mutation(mutation):
                test_url = urljoin(self.base_url, mutation)
                try:
                    # Send unmodified headers to isolate the URI parsing issue
                    resp = self.session.get(test_url, timeout=3, allow_redirects=False)
                    
                    # If we bypassed a 403/401 and got a 200 OK
                    if resp.status_code == 200 and '404' not in resp.text.lower():
                        self.findings.append({
                            'title': '403 Forbidden / Access Control Bypass via URI Normalization',
                            'description': f'Successfully accessed restricted endpoint {path} using {mutation}',
                            'severity': 'CRITICAL',
                            'owasp': 'A01:2021',
                            'api_owasp': 'API1:2023',
                            'cwe': 'CWE-284',
                            'remediation': 'Ensure the reverse proxy (NGINX/Apache) and backend web server normalize URIs identically before enforcing access control rules. Do not rely solely on string-matching URI prefixes.',
                            'evidence': f'Baseline ({path}) returned {baseline_resp.status_code}. Mutation ({mutation}) returned 200 OK.',
                            'mitre_attack': 'T1190'
                        })
                except Exception:
                    pass

            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                executor.map(check_mutation, mutations)
