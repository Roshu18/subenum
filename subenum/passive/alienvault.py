import aiohttp
import logging

class AlienVaultFetcher:
    def __init__(self):
        self.url = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

    async def fetch(self, domain: str) -> set[str]:
        subdomains = set()
        formatted_url = self.url.format(domain=domain)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(formatted_url, timeout=25, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        passive_list = data.get('passive_dns', [])
                        for entry in passive_list:
                            hostname = entry.get('hostname')
                            if hostname and hostname.endswith(domain):
                                subdomains.add(hostname.lower())
        except Exception as e:
            # Return exception for debugging instead of silent fail
            return e
        return subdomains
