import asyncio
import aiohttp
import re
from rich.console import Console

class JavascriptScraper:
    def __init__(self, domain, verbose=False):
        self.domain = domain
        self.verbose = verbose
        self.console = Console()
        # Regex to find subdomains: (alphanumeric+hyphen) . target . com
        # Captures: something.domain.com
        self.regex = re.compile(r'(?:[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+' + re.escape(domain), re.IGNORECASE)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        }

    async def _fetch_text(self, session, url):
        try:
            async with session.get(url, timeout=5, ssl=False) as resp:
                if resp.status == 200:
                    return await resp.text(errors='ignore')
        except Exception:
            pass
        return ""

    async def run(self):
        """
        Crawls the homepage, finds JS files, and scans them for subdomains.
        Returns a set of discovered subdomains.
        """
        found_subdomains = set()
        
        # We need a fresh session here or pass one in. Using a local one for safety/isolation.
        conn = aiohttp.TCPConnector(ssl=False, limit=0, ttl_dns_cache=300)
        async with aiohttp.ClientSession(connector=conn, headers=self.headers) as session:
            
            # 1. Fetch Homepage
            target_url = f"http://{self.domain}"
            if self.verbose:
                self.console.print(f"    [dim]Crawling homepage: {target_url}[/dim]")
            
            home_html = await self._fetch_text(session, target_url)
            if not home_html:
                # Try https if http failed
                target_url = f"https://{self.domain}"
                home_html = await self._fetch_text(session, target_url)
            
            if not home_html:
                return found_subdomains

            # 2. Extract Javascript URLs
            # Looking for src="..." or src='...'
            script_srcs = re.findall(r'<script[^>]+src=["\'](.*?)["\']', home_html, re.IGNORECASE)
            
            # Normalize URLs
            js_urls = set()
            for src in script_srcs:
                if src.startswith("//"):
                    js_urls.add(f"https:{src}")
                elif src.startswith("http"):
                    js_urls.add(src)
                elif src.startswith("/"):
                    # Relative to root
                    base = target_url.rstrip("/")
                    js_urls.add(f"{base}{src}")
                else:
                    # Relative to current path (simplified: just append to base)
                    base = target_url.rstrip("/")
                    js_urls.add(f"{base}/{src}")

            # Limit to top 20 scripts to prevent hanging
            js_urls = list(js_urls)[:20]
            
            if self.verbose:
                self.console.print(f"    [dim]Found {len(js_urls)} unique JS files to scan[/dim]")

            # 3. Fetch JS Files concurrently
            tasks = [self._fetch_text(session, url) for url in js_urls]
            js_contents = await asyncio.gather(*tasks)

            # 4. Scan content (Homepage + JS files)
            all_text_content = [home_html] + list(js_contents)
            
            for content in all_text_content:
                matches = self.regex.findall(content)
                for match in matches:
                    # Basic validation to avoid noise
                    match = match.lower().strip().strip('.')
                    if match.endswith(f".{self.domain}") and match != self.domain:
                        found_subdomains.add(match)

        return found_subdomains
