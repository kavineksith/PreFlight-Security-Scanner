"""
Dynamic Web Crawler & Surface Mapper
Recursively crawls the target web application to discover dynamic links, 
forms, and input vectors that aren't easily bruteforced.
"""

import concurrent.futures
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style

class WebCrawler:
    def __init__(self, session, base_url, max_depth=2, max_pages=100):
        self.session = session
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.to_visit = [(base_url, 0)]  # (url, depth)
        
        # Attack surface collected
        self.discovered_urls = set()
        self.discovered_forms = []
        self.findings = []

    def run_all_checks(self):
        """Execute the web crawl."""
        print(f"{Fore.CYAN}[*] Dynamic Web Surface Crawler{Style.RESET_ALL}")
        self.crawl()
        self._analyze_surface()
        return self.findings

    def crawl(self):
        """Recursively crawl the application using ThreadPool."""
        print(f"{Fore.YELLOW}[*] Crawling application up to depth {self.max_depth} (Max: {self.max_pages} pages)...{Style.RESET_ALL}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            while self.to_visit and len(self.visited) < self.max_pages:
                current_batch = self.to_visit.copy()
                self.to_visit.clear()
                
                # Filter out already visited in this batch
                batch_to_process = []
                for url, depth in current_batch:
                    if url not in self.visited and depth <= self.max_depth:
                        batch_to_process.append((url, depth))
                        self.visited.add(url)
                
                if not batch_to_process:
                    break
                    
                # Execute HTTP requests concurrently
                future_to_url = {executor.submit(self._fetch_and_parse, url, depth): (url, depth) for url, depth in batch_to_process}
                
                for future in concurrent.futures.as_completed(future_to_url):
                    url, depth = future_to_url[future]
                    try:
                        new_links, forms = future.result()
                        self.discovered_urls.update(new_links)
                        self.discovered_forms.extend(forms)
                        
                        # Add new links to queue if within depth
                        if depth < self.max_depth:
                            for link in new_links:
                                if link not in self.visited:
                                    self.to_visit.append((link, depth + 1))
                                    
                    except Exception:
                        pass

    def _fetch_and_parse(self, url, depth):
        """Fetch a single URL and extract HTML links and forms."""
        new_links = set()
        forms_found = []
        
        try:
            resp = self.session.get(url, timeout=5)
            # Only parse HTML
            if 'text/html' not in resp.headers.get('Content-Type', ''):
                return new_links, forms_found
                
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Extract links
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                full_url = urljoin(url, href)
                # Only stay in-scope
                if urlparse(full_url).netloc == self.domain:
                    # Remove fragments
                    full_url = full_url.split('#')[0]
                    new_links.add(full_url)
                    
            # Extract forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').upper()
                form_url = urljoin(url, action)
                
                inputs = []
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    name = input_tag.get('name')
                    if name:
                        inputs.append(name)
                        
                forms_found.append({
                    'source_page': url,
                    'action': form_url,
                    'method': method,
                    'inputs': inputs
                })
                
        except Exception:
            pass
            
        return new_links, forms_found

    def _analyze_surface(self):
        """Report on the discovered attack surface."""
        if self.discovered_urls or self.discovered_forms:
            form_texts = [f"[{f['method']}] {f['action']} (Inputs: {', '.join(f['inputs'])})" for f in self.discovered_forms[:10]]
            
            self.findings.append({
                'title': 'Application Attack Surface Mapped',
                'description': f'Crawler discovered {len(self.discovered_urls)} unique intra-domain links and {len(self.discovered_forms)} HTML forms.',
                'severity': 'INFO',
                'category': 'reconnaissance',
                'evidence': f"Crawled {len(self.visited)} pages.\n\nSample Forms:\n" + "\n".join(form_texts),
                'mitre_attack': 'T1592'
            })
            print(f"{Fore.GREEN}[+] Crawled {len(self.visited)} pages. Found {len(self.discovered_urls)} links and {len(self.discovered_forms)} forms.{Style.RESET_ALL}")
