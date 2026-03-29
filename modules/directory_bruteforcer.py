"""
Directory Brute-Forcer and Sensitive File Discovery
Scans for hidden paths, unprotected administrative interfaces, .git directories, and backup files.
"""

import concurrent.futures
from urllib.parse import urljoin
from colorama import Fore, Style
from modules.payload_updater import PayloadUpdater

class DirectoryBruteforcer:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []
        self.updater = PayloadUpdater()
        
        # Load massive endpoint dictionaries if available, default to curated critical paths
        massive_endpoints = self.updater.load_payloads('api_endpoints.txt', max_payloads=1500)
        massive_files = self.updater.load_payloads('sensitive_files.txt', max_payloads=1500)
        
        self.endpoints = massive_endpoints if massive_endpoints else [
            '.env', '.git/config', '.gitignore', 'docker-compose.yml', '.aws/credentials',
            'backup.zip', 'backup.sql', 'db.sqlite3', 'config.php.bak', '.ssh/id_rsa',
            'wp-config.php.bak', 'admin/', 'administrator/', 'manager/', 'phpmyadmin/',
            'server-status', 'swagger-ui.html', 'api-docs', 'v1/api-docs', 'graphql',
            'actuator/env', 'actuator/health', '.bash_history', 'web.config', 'robots.txt'
        ]
        
        if massive_files and massive_endpoints:
            self.endpoints.extend(massive_files)
            
        # Deduplicate and limit to prevent taking too long on massive scans
        self.endpoints = list(set(self.endpoints))[:2000]

    def run_all_checks(self):
        """Run the directory and file brute-forcer concurrently."""
        print(f"{Fore.CYAN}[*] Directory & Sensitive Config Discovery (DirBust){Style.RESET_ALL}")
        
        discovered_paths = []
        
        # Determine 404 behavior by requesting a completely random string
        baseline_404 = 404
        try:
            resp = self.session.get(urljoin(self.base_url, "random_nonexistent_path_48239"), timeout=5, allow_redirects=False)
            baseline_404 = resp.status_code
        except Exception:
            pass

        def check_path(path):
            if path.startswith('/'):
                path = path[1:]
            url = urljoin(self.base_url, path)
            try:
                response = self.session.get(url, timeout=3, allow_redirects=False)
                status = response.status_code
                
                # If we get a 200 OK, or a 403 (meaning it exists but we can't access it)
                if status in [200, 401, 403] and status != baseline_404:
                    
                    # Ensure we aren't just getting caught by a generic WAF 200 OK catch-all
                    if status == 200 and '404' in response.text.lower():
                        return
                        
                    content_length = len(response.content)
                    discovered_paths.append({
                        'path': f"/{path}",
                        'status': status,
                        'size': content_length
                    })
            except Exception:
                pass

        print(f"{Fore.YELLOW}[*] Brute-forcing {len(self.endpoints)} potential sensitive paths/files...{Style.RESET_ALL}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            executor.map(check_path, self.endpoints)
            
        self._analyze_discoveries(discovered_paths)
        return self.findings

    def _analyze_discoveries(self, paths):
        """Analyze found paths and categorize risk."""
        if not paths:
            return
            
        critical_extensions = ['.env', '.git/config', '.sql', '.bak', '.pem', '.key', 'id_rsa', 'credentials', 'config.php']
        
        generic_discoveries = []
        
        for item in paths:
            path = item['path']
            status = item['status']
            
            # Check for critical leaked infrastructure files
            if status == 200 and any(ext in path for ext in critical_extensions):
                self.findings.append({
                    'title': 'Critical Sensitive File Exposure',
                    'description': f'Highly sensitive configuration or backup file exposed publicly: {path}',
                    'severity': 'CRITICAL',
                    'owasp': 'A05:2021',
                    'cwe': 'CWE-200',
                    'remediation': 'Remove the file from the webroot immediately or explicitly block access via web server rules (e.g., Apache .htaccess or NGINX location block).',
                    'evidence': f'{path} returned 200 OK (Size: {item["size"]} bytes)',
                    'mitre_attack': 'T1552'
                })
            else:
                generic_discoveries.append(f"{path} (HTTP {status})")
                
        if generic_discoveries:
            self.findings.append({
                'title': 'Hidden Directories / API Endpoints Discovered',
                'description': f'DirBuster identified {len(generic_discoveries)} hidden or administrative paths.',
                'severity': 'LOW',
                'category': 'reconnaissance',
                'remediation': 'Ensure all discovered paths require authentication and do not leak sensitive information.',
                'evidence': "\n".join(generic_discoveries[:30]) + ("\n...and more" if len(generic_discoveries) > 30 else "")
            })
