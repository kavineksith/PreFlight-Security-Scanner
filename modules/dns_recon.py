"""
DNS Reconnaissance & Subdomain Discovery Module
Performs DNS enumeration, subdomain brute-force, zone transfer, and takeover detection.
"""

import socket
import json
from pathlib import Path
from urllib.parse import urlparse
from colorama import Fore, Style
from modules.payload_updater import PayloadUpdater

try:
    import dns.resolver
    import dns.zone
    import dns.query
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class DNSRecon:
    def __init__(self, target_url):
        self.target_url = target_url
        self.hostname = urlparse(target_url).hostname or target_url
        self.findings = []
        self.data_dir = Path(__file__).parent.parent / 'data'
        self.updater = PayloadUpdater()

    def run_all_checks(self):
        """Run all DNS reconnaissance checks."""
        print(f"{Fore.CYAN}[*] DNS Reconnaissance: {self.hostname}{Style.RESET_ALL}")

        self.enumerate_dns_records()
        self.check_zone_transfer()
        self.discover_subdomains()
        self.check_email_security()
        self.check_subdomain_takeover()
        self.reverse_dns_lookup()

        return self.findings

    def enumerate_dns_records(self):
        """Enumerate all DNS record types."""
        print(f"{Fore.YELLOW}[*] Enumerating DNS records...{Style.RESET_ALL}")

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA', 'PTR']
        found_records = {}

        for rtype in record_types:
            try:
                if DNS_AVAILABLE:
                    answers = dns.resolver.resolve(self.hostname, rtype)
                    found_records[rtype] = [str(r) for r in answers]
                else:
                    if rtype == 'A':
                        ips = socket.gethostbyname_ex(self.hostname)[2]
                        found_records['A'] = ips
            except Exception:
                continue

        if found_records:
            self.findings.append({
                'title': 'DNS Records Enumeration',
                'description': f'Discovered DNS records for {self.hostname}',
                'severity': 'INFO',
                'category': 'reconnaissance',
                'remediation': 'Review DNS records for unnecessary exposure',
                'evidence': json.dumps(found_records, indent=2),
                'mitre_attack': 'T1596.001'
            })

        # Check for wildcard DNS
        try:
            wild = socket.gethostbyname(f'nonexistent-random-sub-12345.{self.hostname}')
            self.findings.append({
                'title': 'Wildcard DNS Detected',
                'description': f'Wildcard DNS configured — *.{self.hostname} resolves to {wild}',
                'severity': 'LOW',
                'category': 'reconnaissance',
                'remediation': 'Remove wildcard DNS unless intentionally configured',
                'evidence': f'*.{self.hostname} -> {wild}',
                'mitre_attack': 'T1596.001'
            })
        except Exception:
            pass

    def check_zone_transfer(self):
        """Attempt DNS zone transfer (AXFR)."""
        print(f"{Fore.YELLOW}[*] Testing DNS zone transfer...{Style.RESET_ALL}")

        if not DNS_AVAILABLE:
            return

        try:
            ns_records = dns.resolver.resolve(self.hostname, 'NS')
            for ns in ns_records:
                ns_host = str(ns).rstrip('.')
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_host, self.hostname, timeout=5))
                    if zone:
                        records = [str(name) for name in zone.nodes.keys()]
                        self.findings.append({
                            'title': 'DNS Zone Transfer Allowed (AXFR)',
                            'description': f'Zone transfer successful from {ns_host} — exposes all DNS records',
                            'severity': 'HIGH',
                            'category': 'reconnaissance',
                            'cwe': 'CWE-200',
                            'remediation': 'Restrict zone transfers to authorized secondary DNS servers only',
                            'evidence': f'Transferred {len(records)} records from {ns_host}',
                            'mitre_attack': 'T1596.001'
                        })
                        break
                except Exception:
                    continue
        except Exception:
            pass

    def discover_subdomains(self):
        """Brute-force subdomain discovery."""
        print(f"{Fore.YELLOW}[*] Discovering subdomains...{Style.RESET_ALL}")

        massive_subdomains = self.updater.load_payloads('common_subdomains_massive.txt', max_payloads=1000)

        wordlist_path = self.data_dir / 'common_subdomains.txt'
        if wordlist_path.exists() and not massive_subdomains:
            with open(wordlist_path, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        else:
            subdomains = massive_subdomains if massive_subdomains else [
                'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test',
                'beta', 'portal', 'app', 'blog', 'shop', 'cdn', 'static',
                'login', 'dashboard', 'panel', 'vpn', 'remote', 'git', 'jenkins',
                'ci', 'jira', 'confluence', 'grafana', 'monitor', 'backup', 'db',
                'database', 'internal', 'intranet', 'legacy', 'old', 'new', 'v2'
            ]

        discovered = []
        for sub in subdomains:  # Test all loaded subdomains
            fqdn = f"{sub}.{self.hostname}"
            try:
                ip = socket.gethostbyname(fqdn)
                discovered.append({'subdomain': fqdn, 'ip': ip})
            except Exception:
                continue

        if discovered:
            self.findings.append({
                'title': 'Subdomains Discovered',
                'description': f'Found {len(discovered)} subdomains for {self.hostname}',
                'severity': 'INFO',
                'category': 'reconnaissance',
                'remediation': 'Ensure all subdomains are intentional and properly secured',
                'evidence': json.dumps(discovered[:20], indent=2),
                'mitre_attack': 'T1595.002'
            })

    def check_email_security(self):
        """Check SPF, DKIM, and DMARC email security records."""
        print(f"{Fore.YELLOW}[*] Checking email security (SPF/DKIM/DMARC)...{Style.RESET_ALL}")

        # SPF check
        try:
            if DNS_AVAILABLE:
                txt_records = dns.resolver.resolve(self.hostname, 'TXT')
                spf_found = any('v=spf1' in str(r) for r in txt_records)
            else:
                spf_found = False

            if not spf_found:
                self.findings.append({
                    'title': 'Missing SPF Record',
                    'description': 'No SPF record found — domain may be used for email spoofing',
                    'severity': 'MEDIUM',
                    'category': 'email_security',
                    'cwe': 'CWE-290',
                    'remediation': 'Add SPF TXT record to restrict authorized email senders',
                    'evidence': f'No v=spf1 record found for {self.hostname}'
                })
        except Exception:
            pass

        # DMARC check
        try:
            if DNS_AVAILABLE:
                dmarc_records = dns.resolver.resolve(f'_dmarc.{self.hostname}', 'TXT')
                dmarc_text = ' '.join(str(r) for r in dmarc_records)
                if 'p=none' in dmarc_text:
                    self.findings.append({
                        'title': 'Weak DMARC Policy',
                        'description': 'DMARC policy set to "none" — does not protect against spoofing',
                        'severity': 'MEDIUM',
                        'category': 'email_security',
                        'remediation': 'Set DMARC policy to p=quarantine or p=reject',
                        'evidence': f'DMARC: {dmarc_text}'
                    })
            else:
                self.findings.append({
                    'title': 'DMARC Check Skipped',
                    'description': 'dnspython not installed — DMARC check skipped',
                    'severity': 'INFO',
                    'category': 'email_security',
                    'remediation': 'Install dnspython for full DNS checks',
                    'evidence': 'Manual verification required'
                })
        except Exception:
            self.findings.append({
                'title': 'Missing DMARC Record',
                'description': 'No DMARC record found — domain vulnerable to email spoofing',
                'severity': 'MEDIUM',
                'category': 'email_security',
                'remediation': 'Add _dmarc TXT record with p=reject policy',
                'evidence': f'No DMARC record at _dmarc.{self.hostname}'
            })

    def check_subdomain_takeover(self):
        """Check for dangling CNAME records indicating subdomain takeover risk."""
        print(f"{Fore.YELLOW}[*] Checking subdomain takeover risks...{Style.RESET_ALL}")

        takeover_signatures = [
            'herokuapp.com', 'github.io', 'azurewebsites.net',
            'cloudfront.net', 's3.amazonaws.com', 'shopify.com',
            'wordpress.com', 'pantheon.io', 'ghost.io',
            'surge.sh', 'bitbucket.io', 'netlify.app',
            'fly.dev', 'vercel.app', 'render.com'
        ]

        if not DNS_AVAILABLE:
            return

        try:
            cname_records = dns.resolver.resolve(self.hostname, 'CNAME')
            for cname in cname_records:
                cname_target = str(cname).rstrip('.')
                for sig in takeover_signatures:
                    if sig in cname_target:
                        try:
                            socket.gethostbyname(cname_target)
                        except socket.gaierror:
                            self.findings.append({
                                'title': 'Potential Subdomain Takeover',
                                'description': f'Dangling CNAME to {cname_target} — service may be unclaimed',
                                'severity': 'HIGH',
                                'category': 'reconnaissance',
                                'cwe': 'CWE-284',
                                'remediation': 'Remove unused CNAME records or reclaim the service',
                                'evidence': f'{self.hostname} CNAME -> {cname_target} (unresolvable)',
                                'mitre_attack': 'T1584.001'
                            })
        except Exception:
            pass

    def reverse_dns_lookup(self):
        """Perform reverse DNS lookup on target IP."""
        print(f"{Fore.YELLOW}[*] Performing reverse DNS lookup...{Style.RESET_ALL}")

        try:
            ip = socket.gethostbyname(self.hostname)
            try:
                reverse = socket.gethostbyaddr(ip)
                self.findings.append({
                    'title': 'Reverse DNS Lookup',
                    'description': f'IP {ip} resolves to {reverse[0]}',
                    'severity': 'INFO',
                    'category': 'reconnaissance',
                    'remediation': 'Verify reverse DNS is correctly configured',
                    'evidence': f'{ip} -> {reverse[0]} (aliases: {reverse[1]})'
                })
            except Exception:
                self.findings.append({
                    'title': 'No Reverse DNS Record',
                    'description': f'IP {ip} has no reverse DNS (PTR) record',
                    'severity': 'LOW',
                    'category': 'reconnaissance',
                    'remediation': 'Configure reverse DNS for better email deliverability and identification',
                    'evidence': f'{ip} has no PTR record'
                })
        except Exception:
            pass
