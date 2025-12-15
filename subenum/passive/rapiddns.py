import aiohttp
import logging
import re

class RapidDNSFetcher:
    def __init__(self):
        self.url = "https://rapiddns.io/subdomain/{domain}?full=1"

    async def fetch(self, domain: str) -> set[str]:
        subdomains = set()
        formatted_url = self.url.format(domain=domain)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(formatted_url, timeout=30, ssl=False) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        # RapidDNS puts domains in a table. Simple regex works well here.
                        # Pattern: <td>sub.domain.com</td>
                        # But simpler: find all ending in domain
                        pattern = r'[\w\.-]+\.' + re.escape(domain)
                        found = re.findall(pattern, text)
                        for d in found:
                             subdomains.add(d.lower())
        except Exception as e:
            # Return exception for debugging
            return e
        return subdomains
