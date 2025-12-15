
import ipaddress
import re

class TrafficFilter:
    def __init__(self):
        self.private_networks = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8'),
            ipaddress.ip_network('169.254.0.0/16') # Link-local
        ]
        
    def is_private_ip(self, ip_str: str) -> bool:
        """Returns True if IP is private/internal (RFC1918)."""
        if ip_str == "-" or not ip_str:
            return False
            
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in self.private_networks:
                if ip in network:
                    return True
        except ValueError:
            pass
        return False

    def should_ignore_tls_error(self, error_msg: str) -> bool:
        """Returns True if TLS error is just noise (e.g., self-signed common name)."""
        if not error_msg:
            return True
            
        noise_patterns = [
            r"CERT_COMMON_NAME_INVALID", 
            r"certificate verify failed",
            r"self signed certificate",
            r"doesn't match",
            r"SSL: WRONG_VERSION_NUMBER"
        ]
        
        for pattern in noise_patterns:
            if re.search(pattern, error_msg, re.IGNORECASE):
                return True
                
        return False
