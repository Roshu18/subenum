from rich.console import Console
from ..data_classes import DomainResult

class OutputPrinter:
    def __init__(self, console=None):
        self.console = console if console else Console()
        # Define fixed widths for columns
        self.w_ip = 18
        self.w_status = 20
        self.w_type = 10
        self.w_cdn = 30
        # Domain is last, no fixed width needed

    def print_header(self):
        # Manually construct header to match the fixed widths
        header = (
            f"[bold cyan]{'IP Address'.ljust(self.w_ip)}[/bold cyan]"
            f"[bold green]{'Status'.ljust(self.w_status)}[/bold green]"
            f"[bold yellow]{'Type'.ljust(self.w_type)}[/bold yellow]"
            f"[bold blue]{'CDN / Provider'.ljust(self.w_cdn)}[/bold blue]"
            f"[bold white]Domain Name[/bold white]"
        )
        self.console.print(header)
        # Print a separator line compatible with the clean look
        separator = (
            f"[dim]{'─' * (self.w_ip - 2)}  [/dim]"
            f"[dim]{'─' * (self.w_status - 2)}  [/dim]"
            f"[dim]{'─' * (self.w_type - 2)}  [/dim]"
            f"[dim]{'─' * (self.w_cdn - 2)}  [/dim]"
            f"[dim]{'─' * 20}[/dim]"
        )
        self.console.print(separator)

    def print_row(self, result: DomainResult):
        status_str = result.status
        status_style = "dim"

        if result.status == "LIVE":
            if result.http_status > 0:
                status_str = f"LIVE [{result.http_status}]"
                if 200 <= result.http_status < 300:
                    status_style = "bold green"
                elif 300 <= result.http_status < 400:
                    status_style = "bold blue"
                elif 400 <= result.http_status < 500:
                    status_style = "bold yellow"
                elif result.http_status >= 500:
                    status_style = "bold red"
            else:
                status_str = "LIVE [DNS]" # Clarify that it's only DNS-resolvable
                status_style = "green"
        elif result.status == "DEAD":
             status_style = "red"
        elif result.status == "WILDCARD":
             status_style = "bold yellow"

        provider = result.provider
        provider_style = "magenta" if "CDN" in provider else "white"
        
        # Truncate CDN if too long to prevent breaking alignment
        if len(provider) > self.w_cdn - 2:
            provider = provider[:self.w_cdn - 3] + "…"
            
        # Format string with padding
        # Note: We must padding *before* coloring for ljust to work on content length, 
        # but rich tags mess up len(). 
        # Easier strategy: Use simple spacing strings.
        
        # Define "Critical" keywords (Very Sensitive) -> RED
        CRITICAL_KEYWORDS = [
            'admin', 'vpn', 'secret', 'internal', 'private', 'secure', 'auth', 
            'login', 'signin', 'account', 'jenkins', 'k8s', 'kube', 'git', 
            'db', 'sql', 'redis', 'backup', 'confidential', 'root', 'ssh'
        ]

        # Define "Juicy" keywords (Interesting) -> YELLOW
        JUICY_KEYWORDS = [
            # Environments
            'dev', 'stage', 'stg', 'test', 'uat', 'beta', 'alpha', 'prod', 'preprod',
            'qa', 'sandbox', 'demo', 'lab',
            # Panels & Management
            'panel', 'dashboard', 'portal', 'mgmt', 'manage', 'register', 'signup',
            'corp', 'hidden',
            # Data & Tech
            'api', 'graphql', 'swagger', 'files', 'upload', 'download',
            'database', 'elasticsearch', 'docker', 'gitlab', 
            # Cloud
            'aws', 's3', 'bucket', 'azure', 'blob', 'gcp', 'cloudflare',
            'cdn', 'origin', 'edge',
            # Services
            'mail', 'email', 'exchange', 'smtp', 'remote',
            'jira', 'confluence', 'slack', 'grafana', 'kibana', 'prometheus'
        ]
        
        domain_style = "white"
        
        # Check Critical first (Red)
        is_critical = False
        for keyword in CRITICAL_KEYWORDS:
            if keyword in result.domain.lower():
                domain_style = "bold red"
                is_critical = True
                break
        
        # If not critical, check Juicy (Yellow)
        if not is_critical:
            for keyword in JUICY_KEYWORDS:
                if keyword in result.domain.lower():
                    domain_style = "bold yellow"
                    break
        
        row = (
            f"[cyan]{result.ip.ljust(self.w_ip)}[/cyan]"
            f"[{status_style}]{status_str.ljust(self.w_status)}[/{status_style}]"
            f"[yellow]{result.rtype.ljust(self.w_type)}[/yellow]"
            f"[{provider_style}]{provider.ljust(self.w_cdn)}[/{provider_style}]"
            f"[{domain_style}]{result.domain}[/{domain_style}]"
        )
        
        self.console.print(row)
