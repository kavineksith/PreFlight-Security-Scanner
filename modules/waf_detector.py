"""
Web Application Firewall (WAF) and Technology Stack Detector
Attempts to fingerprint the presence of defensive WAFs (Cloudflare, Akamai, Imperva)
and specific web server technologies beyond basic headers.
"""

import requests
from urllib.parse import urljoin
from colorama import Fore, Style

class WAFDetector:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []
        
        # Signatures mapping to WAFs based on headers or blocking behavior
        self.waf_signatures = {
            'Cloudflare': {'headers': ['CF-RAY', 'CF-Cache-Status', 'Expect-CT'], 'cookies': ['__cfduid', 'cf_clearance']},
            'Akamai': {'headers': ['X-Akamai-Transformed', 'Akamai-Origin-Hop']},
            'AWS WAF': {'headers': ['X-Amzn-RequestId', 'X-Amz-Cf-Id'], 'cookies': ['AWSALB']},
            'Imperva / Incapsula': {'headers': ['X-Iinfo', 'X-CDN'], 'cookies': ['incap_ses', 'visid_incap']},
            'F5 BIG-IP': {'headers': ['X-Cnection', 'X-WA-Info'], 'cookies': ['BIGipServer', 'F5_ST']},
            'Sucuri': {'headers': ['X-Sucuri-ID', 'X-Sucuri-Cache']},
            'ModSecurity': {'headers': [], 'blocking_pattern': ['ModSecurity Action', 'Not Acceptable', '406']}
        }

    def run_all_checks(self):
        """Run WAF / Tech Stack identification."""
        print(f"{Fore.CYAN}[*] WAF & Tech Stack Detection{Style.RESET_ALL}")
        
        self.detect_waf()
        
        return self.findings

    def detect_waf(self):
        """Trigger suspicious behavior to see what WAF catches it and how it responds."""
        print(f"{Fore.YELLOW}[*] Probing for Web Application Firewalls...{Style.RESET_ALL}")
        
        detected_wafs = []
        
        # We send a heavily benign baseline, and a highly malicious payload
        url = urljoin(self.base_url, '/?test=1')
        malicious_url = urljoin(self.base_url, '/?id=1+AND+1=1+UNION+SELECT+1,2,3--&xss=<script>alert(1)</script>')
        
        try:
            baseline = self.session.get(url, timeout=5)
            attack_resp = self.session.get(malicious_url, timeout=5)
            
            # Analyze baseline headers for passive WAF signatures
            headers_str = str(baseline.headers)
            cookies_str = str(baseline.cookies.get_dict())
            
            for waf_name, sigs in self.waf_signatures.items():
                for h in sigs.get('headers', []):
                    if h.lower() in headers_str.lower():
                        detected_wafs.append(waf_name)
                for c in sigs.get('cookies', []):
                    if c.lower() in cookies_str.lower():
                        detected_wafs.append(waf_name)
                        
            # Analyze active blocking (if baseline is 200 but attack is 403/406/501)
            if baseline.status_code == 200 and attack_resp.status_code in [403, 406, 501, 503]:
                # Look for ModSecurity or generic block pages
                resp_text = attack_resp.text.lower()
                for waf_name, sigs in self.waf_signatures.items():
                    for pattern in sigs.get('blocking_pattern', []):
                        if pattern.lower() in resp_text:
                            detected_wafs.append(waf_name)
                            
                if not detected_wafs:
                    detected_wafs.append("Generic/Unknown WAF")

        except Exception:
            pass
            
        detected_wafs = list(set(detected_wafs))
        
        if detected_wafs:
            self.findings.append({
                'title': 'Web Application Firewall (WAF) Detected',
                'description': f'Identified active blocking or proxy routing by: {", ".join(detected_wafs)}',
                'severity': 'INFO',
                'category': 'reconnaissance',
                'evidence': f'Malicious payload requests triggered protective behaviors linked to {detected_wafs}.'
            })
            print(f"{Fore.GREEN}[+] WAF Detected: {', '.join(detected_wafs)}{Style.RESET_ALL}")
        else:
            self.findings.append({
                'title': 'No WAF Protection Detected',
                'description': 'The application appears to lack an active Web Application Firewall for input inspection.',
                'severity': 'MEDIUM',
                'category': 'configuration',
                'remediation': 'Implement a WAF (like AWS WAF, Cloudflare, or ModSecurity) to actively block common attacks (SQLi, XSS) before they hit the application layer.',
                'evidence': 'Malicious payloads (SQLi/XSS) passed through to the backend without interception or generic 403 blocking.'
            })
            print(f"{Fore.RED}[!] No WAF detected during malicious payload testing.{Style.RESET_ALL}")
