from dataclasses import dataclass

@dataclass
class DomainResult:
    domain: str
    ip: str = "-"
    status: str = "UNKNOWN"  # LIVE, DEAD, WILDCARD
    rtype: str = "-"         # A, CNAME
    cname: str = ""          # CNAME value for takeover detection
    provider: str = ""       # CDN info
    http_status: int = 0     # 200, 404, 500, etc.
    waf: str = ""
    title: str = ""
    content_length: int = 0
    location: str = ""
    score: int = 0           # Risk score
    risk_reasons: list = None  # Risk categories
    is_takeover: bool = False
    takeover_service: str = ""

    def __post_init__(self):
        if self.risk_reasons is None:
            self.risk_reasons = []

    def __hash__(self):
        return hash(self.domain)

