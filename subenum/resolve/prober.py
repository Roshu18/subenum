import asyncio
import aiohttp
import ssl
import re
from collections import Counter

class AsyncProber:
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
    
    def _detect_waf(self, headers, cookies):
        signatures = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cf-cache-status'],
            'AWS CloudFront': ['x-amz-cf-id', 'via'],
            'Akamai': ['x-akamai-transformed', 'akamai-origin-hop'],
            'Imperva': ['x-iinfo', 'incap-ses'],
            'F5 BIG-IP': ['bigipServer'],
            'Sucuri': ['x-sucuri-id'],
        }
        
        for name, keys in signatures.items():
            for key in keys:
                if key in headers or any(key in c for c in cookies or []):
                    if name == 'AWS CloudFront' and key == 'via':
                         val = headers.get('via', '').lower()
                         if 'cloudfront' in val:
                             return name
                         continue
                    return name
        return None

    def _extract_title(self, text):
        if not text:
            return ""
        match = re.search(r'<title>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:100]
        return ""

    def _extract_structure(self, text):
        """ Returns a Counter of HTML tags (e.g., {'div': 10, 'a': 5}) """
        if not text:
            return Counter()
        # Find all start tags
        tags = re.findall(r'<([a-zA-Z0-9]+)', text)
        return Counter([t.lower() for t in tags])

    async def _probe_with_session(self, url, session):
        try:
            # First try HEAD
            async with session.head(url, timeout=self.timeout, allow_redirects=True) as resp:
                waf = self._detect_waf(resp.headers, resp.cookies)
                location = resp.headers.get('Location', "")
                status = resp.status
                length = int(resp.headers.get('Content-Length', 0))
                
                # If 200/403/500, we need body for structural fingerprinting
                if status not in [200, 403, 500]:
                     return status, waf, "", length, location, Counter(), ""

            # GET for body
            async with session.get(url, timeout=self.timeout, allow_redirects=True) as resp:
                text = await resp.text(errors='ignore')
                title = self._extract_title(text)
                length = len(text)
                structure = self._extract_structure(text)
                waf = self._detect_waf(resp.headers, resp.cookies) or waf
                location = resp.headers.get('Location', "") or location
                # Return body text (truncated to 5000 chars for takeover detection)
                return resp.status, waf, title, length, location, structure, text[:5000]

        except Exception:
            return 0, None, "", 0, "", Counter(), ""

    async def probe(self, domain, session=None):
        """
        Returns tuple: (status_code, waf_name, title, content_length, location, structure_map, body_text)
        """
        local_session = False
        if session is None:
            conn = aiohttp.TCPConnector(ssl=False, limit=0, ttl_dns_cache=300)
            session = aiohttp.ClientSession(connector=conn, headers=self.headers)
            local_session = True

        try:
            # 1. Try HTTPS
            url = f"https://{domain}"
            res = await self._probe_with_session(url, session)
            if res[0] != 0:
                return res

            # 2. Try HTTP
            url = f"http://{domain}"
            return await self._probe_with_session(url, session)
        
        finally:
            if local_session:
                await session.close()

