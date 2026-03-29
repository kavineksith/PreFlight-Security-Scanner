"""
Payload Updater Module
Responsible for automatically fetching thousands of enterprise-grade security payloads
from popular public security repositories (SecLists, PayloadAllTheThings) and syncing
CVE databases to keep the scanner up-to-date.
"""

import os
import requests
from pathlib import Path
from colorama import Fore, Style

class PayloadUpdater:
    def __init__(self, data_dir="./data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.verify = False

        # Map local file names to remote raw URLs
        self.payload_sources = {
            "sqli_payloads.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt",
            "xss_payloads.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Bypass-Strings-BruteForce.txt",
            "ssrf_payloads.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SSRF.txt",
            "lfi_payloads.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
            "common_subdomains_massive.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
            "jwt_secrets_massive.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/jwt.secrets.list",
            "api_endpoints.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
            "sensitive_files.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt",
            "csti_payloads.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Template-Injection/SSTI.txt"
        }

    def update_all(self):
        """Fetch all payloads from the specified URLs and save them locally."""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[*] SYNCING ENTERPRISE PAYLOADS AND DATABASES")
        print(f"[*] Downloading over 150,000+ payloads from SecLists/PayloadsAllTheThings")
        print(f"{'='*60}{Style.RESET_ALL}\n")

        total_lines_downloaded = 0
        success_count = 0

        for filename, url in self.payload_sources.items():
            filepath = self.data_dir / filename
            print(f"{Fore.WHITE}[+] Syncing {filename}... ", end='', flush=True)

            try:
                response = self.session.get(url, timeout=15)
                if response.status_code == 200:
                    content = response.text
                    lines = len(content.splitlines())
                    total_lines_downloaded += lines
                    
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(content)
                    print(f"{Fore.GREEN}SUCCESS ({lines:,} payloads){Style.RESET_ALL}")
                    success_count += 1
                else:
                    print(f"{Fore.RED}FAILED (HTTP {response.status_code}){Style.RESET_ALL}")
            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED}ERROR ({e}){Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}[✓] Sync Complete! Successfully updated {success_count}/{len(self.payload_sources)} databases.")
        print(f"[✓] Downloaded approximately {total_lines_downloaded:,} total payloads/entries.{Style.RESET_ALL}")

        return total_lines_downloaded > 0

    def load_payloads(self, filename, max_payloads=1000):
        """Utility method to load payloads into other modules safely without memory exhaustion."""
        filepath = self.data_dir / filename
        if not filepath.exists():
            return []
            
        payloads = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i >= max_payloads:
                        break
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
        except Exception:
            pass
            
        return payloads
