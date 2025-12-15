import aiohttp
import logging
from ..data_classes import DomainResult

class CrtShFetcher:
    def __init__(self):
        self.url = "https://crt.sh/?q=%.{domain}&output=json"

    async def fetch(self, domain: str) -> set[str]:
        subdomains = set()
        formatted_url = self.url.format(domain=domain)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(formatted_url, timeout=30, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            # Split multiple domains in one cert
                            for sub in name_value.split('\n'):
                                if '*' not in sub:
                                    subdomains.add(sub.lower())
        except Exception as e:
            # Return exception for debugging
            return e
        return subdomains
