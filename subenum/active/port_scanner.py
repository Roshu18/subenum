import asyncio
import socket

class PortScanner:
    """
    Fast async port scanner for discovered subdomains.
    Scans common web service ports.
    """
    
    def __init__(self):
        # Common web service ports
        self.ports = [80, 443, 8080, 8443, 3000, 8000, 8888, 9000]
    
    async def scan_port(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """
        Check if a port is open on the host.
        Returns True if open, False otherwise.
        """
        try:
            # Create connection with timeout
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False
    
    async def scan_host(self, host: str) -> dict:
        """
        Scan all ports on a host.
        Returns dict of {port: is_open}
        """
        tasks = [self.scan_port(host, port) for port in self.ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        open_ports = []
        for i, result in enumerate(results):
            if result is True:
                open_ports.append(self.ports[i])
        
        return {
            'host': host,
            'open_ports': open_ports,
            'total_scanned': len(self.ports)
        }
