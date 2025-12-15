
import asyncio
import aiohttp
from subenum.passive.rapiddns import RapidDNSFetcher
from subenum.passive.alienvault import AlienVaultFetcher

async def test():
    domain = "tesla.com"
    print(f"Testing Backup Sources for {domain}...")

    print("\n--- Testing RapidDNS ---")
    r = RapidDNSFetcher()
    res = await r.fetch(domain)
    print(f"Found: {len(res)}")
    print(list(res)[:5])

    print("\n--- Testing AlienVault ---")
    a = AlienVaultFetcher()
    res = await a.fetch(domain)
    print(f"Found: {len(res)}")
    print(list(res)[:5])

if __name__ == "__main__":
    if asyncio.get_event_loop_policy().__class__.__name__ != 'WindowsSelectorEventLoopPolicy':
         asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(test())
