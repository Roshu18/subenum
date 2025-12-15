import aiohttp
import logging

class HackerTargetFetcher:
    def __init__(self):
        self.url = "https://api.hackertarget.com/hostsearch/?q={domain}"

    async def fetch(self, domain: str) -> set[str]:
        subdomains = set()
        formatted_url = self.url.format(domain=domain)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(formatted_url, timeout=25, ssl=False) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.split('\n'):
                            if ',' in line:
                                host, _ = line.split(',', 1)
                                host = host.lower()
                                if host.endswith(domain): 
                                    subdomains.add(host)
        except Exception as e:
            # Return exception for debugging instead of silent fail
            return e
        return subdomains
