"""
Advanced Port Scanner & Protocol Identifier
Scans the top 100 enterprise ports rapidly using threads and attempts to identify running protocols/banners.
"""

import socket
import concurrent.futures
from urllib.parse import urlparse
from colorama import Fore, Style

class PortScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.hostname = urlparse(target_url).hostname or target_url
        self.findings = []
        
        # Top 50 commercial enterprise/attack surface ports
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 1521: 'Oracle', 2049: 'NFS', 2181: 'ZooKeeper',
            2375: 'Docker', 2379: 'etcd', 3306: 'MySQL', 3389: 'RDP', 
            4369: 'RabbitMQ', 5432: 'PostgreSQL', 5672: 'RabbitMQ', 5900: 'VNC',
            6379: 'Redis', 8000: 'HTTP-Alt', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
            9000: 'SonarQube/PHP-FPM', 9042: 'Cassandra', 9092: 'Kafka', 
            9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB', 50000: 'SAP'
        }

    def run_all_checks(self):
        """Run the comprehensive port and protocol scanning."""
        print(f"{Fore.CYAN}[*] Port Scanning & Protocol Identification for: {self.hostname}{Style.RESET_ALL}")
        
        try:
            target_ip = socket.gethostbyname(self.hostname)
        except socket.gaierror:
            print(f"{Fore.RED}[!] Could not resolve hostname {self.hostname} for port scanning.{Style.RESET_ALL}")
            return self.findings

        # Scan ports concurrently
        open_ports = []
        
        def scan_port(port, service_name):
            try:
                sock = socket.socket(socket.AF_INET, socket.socket.SOCK_STREAM)
                sock.settimeout(1.5)  # Fast scan
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    banner = self.grab_banner(target_ip, port)
                    open_ports.append({
                        'port': port,
                        'service': service_name,
                        'banner': banner.strip() if banner else "No Banner Detected"
                    })
                sock.close()
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for port, service in self.common_ports.items():
                executor.submit(scan_port, port, service)

        # Process the findings
        self._analyze_open_ports(open_ports, target_ip)

        return self.findings
        
    def grab_banner(self, ip, port):
        """Attempt to grab the service banner to identify protocol details."""
        try:
            sock = socket.socket(socket.AF_INET, socket.socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((ip, port))
            
            # Send an HTTP-like request as a prod to see if it's a web server
            if port in [80, 443, 8080, 8443]:
                if port in [443, 8443]:
                    # Quick grab for HTTPS would involve SSL wrapper, skipping for fast scan
                    pass
                else:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner[:150] # Return first 150 chars max
        except Exception:
            return None

    def _analyze_open_ports(self, open_ports, ip):
        if not open_ports:
            return
            
        # Compile all open ports into a single consolidated finding to avoid clutter
        port_list = []
        critical_exposures = []
        
        # High risk ports that shouldn't be exposed to the internet
        high_risk_ports = [21, 22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 11211, 27017]

        for p in open_ports:
            port_num = p['port']
            port_list.append(f"Port {port_num} ({p['service']}) - Banner: {p['banner'][:50]}")
            
            if port_num in high_risk_ports:
                critical_exposures.append(f"{port_num} ({p['service']})")

        self.findings.append({
            'title': 'Network Port Scan Results',
            'description': f'Identified {len(open_ports)} open ports and protocols on {ip}',
            'severity': 'INFO',
            'category': 'reconnaissance',
            'remediation': 'Close all non-essential ports to minimize external attack surface. Only ports 80/443 should typically be exposed on a web application server.',
            'evidence': "\n".join(port_list),
            'mitre_attack': 'T1046'
        })
        
        if critical_exposures:
            self.findings.append({
                'title': 'High-Risk Network Services Exposed',
                'description': f'Critical database or administrative services exposed to the public internet: {", ".join(critical_exposures)}',
                'severity': 'HIGH',
                'category': 'reconnaissance',
                'cwe': 'CWE-200',
                'remediation': 'Immediately block public access to these ports using a firewall (AWS Security Groups, iptables, etc.) and restrict access to internal IPs or VPNs.',
                'evidence': f"Exposed high-risk ports: {', '.join(critical_exposures)}",
                'mitre_attack': 'T1190'
            })
