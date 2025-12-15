import asyncio
import aiodns

async def test_dns():
    loop = asyncio.get_running_loop()
    resolver = aiodns.DNSResolver(loop=loop, nameservers=['8.8.8.8'])
    try:
        res = await resolver.query('google.com', 'A')
        print(f"DNS Success: {res[0].host}")
    except Exception as e:
        print(f"DNS Error: {e}")

if __name__ == '__main__':
    import sys
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(test_dns())
