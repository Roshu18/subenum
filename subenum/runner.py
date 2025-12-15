import asyncio
import aiohttp
import logging
import random
from rich.live import Live
from rich.console import Console
from rich.table import Table

# Suppress annoying asyncio task destruction errors on Windows
logging.getLogger("asyncio").setLevel(logging.CRITICAL)

from .passive.crtsh import CrtShFetcher
from .passive.hackertarget import HackerTargetFetcher
from .passive.rapiddns import RapidDNSFetcher
from .passive.alienvault import AlienVaultFetcher
from .passive.wayback import WaybackFetcher
from .passive.threatminer import ThreatMinerFetcher
from .passive.axfr import AXFRChecker
from .active.brute import BruteForcer
from .resolve.resolver import AsyncResolver
from .resolve.prober import AsyncProber
from .active.mutator import Mutator
from .active.scraper import JavascriptScraper
from .active.port_scanner import PortScanner
from .active.nuclei_scanner import NucleiScanner
from .active.recursive_enum import RecursiveEnumerator
from .output.printer import OutputPrinter
from .output.exporter import ResultExporter
from .analysis import TrafficFilter, TakeoverDetector, RiskScorer, SmartFingerprinter

class Runner:
    def __init__(self, domain, concurrency=10, deep_scan=False, wordlist=None, verbose=False,
                 output_file=None, output_format='json', recursive=False, axfr=False,
                 enable_ports=False, enable_nuclei=False):
        # Sanitize domain input (Common User Error Fix)
        self.domain = domain.replace("https://", "").replace("http://", "").split("/")[0].strip()
        
        self.concurrency = concurrency
        self.deep_scan = deep_scan
        self.wordlist = wordlist
        self.verbose = verbose
        self.output_file = output_file
        self.output_format = output_format.lower()
        self.recursive = recursive
        self.axfr = axfr
        self.enable_ports = enable_ports
        self.enable_nuclei = enable_nuclei
        
        self.console = Console()
        self.brute_forcer = BruteForcer(self.domain, deep_scan=deep_scan, custom_path=wordlist)
        self.mutator = Mutator(self.domain)
        self.scraper = JavascriptScraper(self.domain, verbose=verbose)
        self.prober = AsyncProber()
        self.printer = OutputPrinter(self.console)
        self.exporter = ResultExporter()
        self.axfr_checker = AXFRChecker() if axfr else None
        self.port_scanner = PortScanner() if enable_ports else None
        self.nuclei_scanner = NucleiScanner(verbose=verbose) if enable_nuclei else None
        self.recursive_enum = None  # Will initialize later with passive sources
        
        # Analysis Engine (The Brain)
        self.traffic_filter = TrafficFilter()
        self.takeover_detector = TakeoverDetector()
        self.risk_scorer = RiskScorer()
        self.fingerprinter = SmartFingerprinter()
        
        self.session = None
        
        # Concurrency Control
        # Semaphore limits concurrent HTTP requests to prevent overwhelming targets
        self.http_semaphore = asyncio.Semaphore(min(50, concurrency * 5))
        
        # Progress Tracking
        self.total_candidates = 0
        self.processed_count = 0
        self.success_count = 0
        self.error_count = 0
        
        # Initialize passive sources
        self.passive_sources = [
            CrtShFetcher(),
            HackerTargetFetcher(),
            RapidDNSFetcher(),
            AlienVaultFetcher(),
            WaybackFetcher(),
            # ThreatMinerFetcher()
        ]
        self.all_findings = []

    async def _collect_passive(self):
        self.console.print("\n[bold yellow]Phase 1: Passive Discovery[/bold yellow]")
        
        # Gather tasks
        tasks = [s.fetch(self.domain) for s in self.passive_sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_subs = set()
        for i, res in enumerate(results):
            source = self.passive_sources[i]
            if isinstance(res, set):
                count = len(res)
                all_subs.update(res)
                if count > 0:
                    self.console.print(f"    + [green]{source.__class__.__name__}[/green] found {count}")
                    if self.verbose: 
                        # Show ALL raw findings if verbose
                        for sub in sorted(res):
                            self.console.print(f"[dim]    > Found:[/dim] [cyan]{sub}[/cyan] [dim]({source.__class__.__name__})[/dim]")
            else:
                # Show error details
                error_msg = str(res) if res else "Unknown error"
                self.console.print(f"    - [red]{source.__class__.__name__}[/red] failed: [dim]{error_msg}[/dim]")
                if self.verbose:
                    self.console.print(f"      [dim]Full error: {error_msg}[/dim]")
        
        # --- AXFR ATTEMPT ---
        if self.axfr_checker:
            self.console.print("    [yellow]Attempting DNS Zone Transfer (AXFR)...[/yellow]")
            axfr_subs = await self.axfr_checker.attempt_transfer(self.domain)
            if axfr_subs:
                all_subs.update(axfr_subs)
                self.console.print(f"    + [green]AXFR[/green] found {len(axfr_subs)} [bold](Zone Transfer Successful!)[/bold]")
                if self.verbose:
                    for sub in sorted(axfr_subs):
                        self.console.print(f"[dim]    > Found:[/dim] [cyan]{sub}[/cyan] [dim](AXFR)[/dim]")
            else:
                self.console.print(f"    - [dim]AXFR failed (server not misconfigured)[/dim]")
        
        unique_passive = len(all_subs)
        self.console.print(f"[bold]Unique Passive Subdomains:[/bold] {unique_passive}")
        
        return all_subs

    async def start(self):
        self.resolver = AsyncResolver(nameservers=['8.8.8.8', '1.1.1.1', '1.0.0.1', '208.67.222.222']) 
        
        if self.wordlist:
            mode_str = f"Custom Wordlist ({self.wordlist})"
        elif self.deep_scan:
            mode_str = "Full Scan (Top-110k Wordlist)"
        else:
            mode_str = "Safe Scan (Curated List)"
        
        self.console.print(f"[bold cyan]Target:[/bold cyan] {self.domain}")
        self.console.print(f"[bold yellow]Mode:[/bold yellow] {mode_str}")
        self.console.print(f"[dim]Concurrency: {self.concurrency}[/dim]")
        
        # Helper to track what we've queued to avoid duplicates
        processed_candidates = set()
        queue = asyncio.Queue()

        # --- SETUP SESSION & WILDCARD DETECTION FIRST ---
        # Create shared session early
        conn = aiohttp.TCPConnector(ssl=False, limit=0, ttl_dns_cache=300)
        self.session = aiohttp.ClientSession(connector=conn, headers=self.prober.headers)
        
        # --- PHASE 0: WILDCARD DETECTION ---
        self.console.print("\n[bold]Phase 0: Wildcard Detection[/bold]")
        wildcard_ips = set()
        wildcard_signatures = []
        
        # Test 3 random subdomains (Subfinder best practice)
        for i in range(3):
            import random
            import string
            rand_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            test_domain = f"wildcard_canary_{rand_sub}.{self.domain}"
            
            self.console.print(f"  Probing random subdomain {i+1}/3: {test_domain}")
            res = await self.resolver.resolve(test_domain)
            
            if res.status == "LIVE":
                wildcard_ips.add(res.ip)
                # Probe HTTP to get signature
                code, waf, title, length, location, structure, body = await self.prober.probe(test_domain, session=self.session)
                wildcard_signatures.append({
                    'code': code,
                    'title': title,
                    'length': length,
                    'structure': structure
                })
        
        if wildcard_ips:
            self.console.print(f"  [bold red]Wildcard DNS detected![/bold red] IPs: {', '.join(wildcard_ips)}")
            self.console.print(f"  [yellow]Will filter out {len(wildcard_ips)} wildcard IPs and {len(wildcard_signatures)} signatures[/yellow]")
        else:
            self.console.print(f"  [green]No Wildcard DNS detected.[/green]")

        # --- START WORKERS IMMEDIATELY ---
        self.console.print(f"\n[bold]Starting Scan workers...[/bold] [dim](Higher priority findings will appear first)[/dim]")
        self.printer.print_header()
        async def worker():
            while True:
                sub = await queue.get()
                try:
                    # 1. Resolve (DNS doesn't need semaphore)
                    res = await self.resolver.resolve(sub)
                    
                    # --- ANALYSIS: PRIVATE IP FILTER (Hard Drop) ---
                    if self.traffic_filter.is_private_ip(res.ip):
                        # Silently drop private/internal IPs
                        self.processed_count += 1
                        continue

                    if res.status == "LIVE":
                        # WILDCARD IP FILTER
                        if res.ip in wildcard_ips:
                            self.processed_count += 1
                            continue

                        # 2. Probe HTTP (Use semaphore to limit concurrent HTTP requests)
                        async with self.http_semaphore:
                            code, waf, title, length, location, structure, body = await self.prober.probe(sub, session=self.session)
                        
                        # --- ANALYSIS: TLS FILTER ---
                        # (Implicitly handled by prober asking for ssl=False, but we could check errors here if we had them)

                        res.http_status = code
                        res.waf = waf
                        res.title = title
                        res.content_length = length
                        res.location = location
                        
                        # WILDCARD STRUCTURE FILTER
                        is_false_positive = False
                        for sig in wildcard_signatures:
                            if code == sig['code']:
                                if title == sig['title'] or abs(length - sig['length']) < 50:
                                    is_false_positive = True
                                    break
                                if sig['structure'] and structure:
                                    diff_count = 0
                                    total_tags = sum(sig['structure'].values())
                                    for tag, count in sig['structure'].items():
                                        diff_count += abs(count - structure.get(tag, 0))
                                    if total_tags > 0 and (diff_count / total_tags) < 0.10:
                                        is_false_positive = True
                                        break
                                    if total_tags == 0 and sum(structure.values()) == 0:
                                        pass

                        if is_false_positive:
                            self.processed_count += 1
                            continue

                        # --- ANALYSIS: SMART DEDUPLICATION ---
                        # Hash the content to find duplicates
                        content_hash = self.fingerprinter.get_hash(code, title, length, body[:500])
                        if self.fingerprinter.is_duplicate(content_hash):
                            self.processed_count += 1
                            continue # Drop duplicate content

                        # --- ANALYSIS: TAKEOVER CHECK ---
                        # Now we have the body text for proper takeover detection
                        takeover_risk = self.takeover_detector.check(res.cname, body)
                        if takeover_risk:
                            res.is_takeover = True
                            res.takeover_service = takeover_risk

                        # --- ANALYSIS: RISK SCORING ---
                        # Calculate Score
                        score, reasons = self.risk_scorer.calculate_score(
                            sub, code, title, 
                            False, # already filtered private 
                            takeover_risk
                        )
                        
                        res.score = score
                        res.risk_reasons = reasons
                        
                        # --- PORT SCANNING (if enabled) ---
                        if self.port_scanner:
                            port_results = await self.port_scanner.scan_host(res.domain)
                            if port_results['open_ports']:
                                # Add open ports to risk reasons
                                ports_str = ', '.join(map(str, port_results['open_ports']))
                                res.risk_reasons.append(f"Open ports: {ports_str}")
                                # Boost score for non-standard ports
                                non_standard = [p for p in port_results['open_ports'] if p not in [80, 443]]
                                if non_standard:
                                    res.score += len(non_standard)
                        
                        # Collect for summary
                        self.all_findings.append(res)
                        self.success_count += 1

                        # Update WAF provider info
                        if waf:
                            if res.provider and res.provider != "-":
                                if waf not in res.provider:
                                    res.provider = f"{waf} / {res.provider}"
                            else:
                                res.provider = waf
                        
                        # --- SHOW ALL LIVE FINDINGS ---
                        # Display every live subdomain in the table
                        self.printer.print_row(res)
                    
                    self.processed_count += 1
                
                except Exception as e:
                    self.error_count += 1
                    self.processed_count += 1
                    if self.verbose:
                        self.console.print(f"[dim red]Worker error on {sub}: {str(e)[:100]}[/dim red]")
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]

        # --- PHASE 1: PASSIVE (PRIORITY 1) ---
        # self.console.print("\n[bold yellow]Phase 1: Passive Discovery[/bold yellow]") # Skipping header to keep table clean? No, printing normally
        # Actually, headers might mess up the table. Let's just log "Queuing Passive..."
        
        passive_subs = await self._collect_passive()
        for sub in passive_subs:
            if sub not in processed_candidates:
                processed_candidates.add(sub)
                queue.put_nowait(sub)
        
        # --- PHASE 1.5: JS SCRAPING (PRIORITY 2) ---
        self.console.print("\n[bold]Phase 1.5: Recursive JS Scraping[/bold]")
        js_subs = await self.scraper.run()
        if js_subs:
            self.console.print(f"  [cyan]>[/cyan] Found {len(js_subs)} subdomains in JS")
            self.console.print(f"    [bold cyan]Findings (JS Scraped):[/bold cyan]")
            
            # Print ALL findings in a clean wrapped list
            sorted_subs = sorted(list(js_subs))
            self.console.print(f"    [cyan]{', '.join(sorted_subs)}[/cyan]")
            
            for sub in js_subs:
                if sub not in processed_candidates:
                    processed_candidates.add(sub)
                    queue.put_nowait(sub)
        else:
             self.console.print("  [dim]No subdomains found in JS files.[/dim]")


        # --- PHASE 2: BRUTE FORCE (PRIORITY 3) ---
        self.console.print("\n[bold]Phase 2: Brute Force[/bold]")
        brute_subs = await self.brute_forcer.generate_candidates()
        self.console.print(f"  [cyan]>[/cyan] Generated {len(brute_subs)} candidates")
        for sub in brute_subs:
            if sub not in processed_candidates:
                processed_candidates.add(sub)
                queue.put_nowait(sub)

        # --- PHASE 2.5: PERMUTATIONS (PRIORITY 4) ---
        if len(processed_candidates) > 0: # Use processed_candidates as seeds
             self.console.print("\n[bold]Phase 2.5: Permutation Scanning[/bold]")
             # Only mutate what we found so far? Or everything? 
             # Convention: Mutate passive + brute findings.
             perm_subs = self.mutator.generate_permutations(processed_candidates)
             self.console.print(f"  [cyan]>[/cyan] Generated {len(perm_subs)} variants")
             for sub in perm_subs:
                 if sub not in processed_candidates:
                     processed_candidates.add(sub)
                     queue.put_nowait(sub)       

        self.console.print(f"[bold green]Total Unique Candidates Queued: {len(processed_candidates)}[/bold green]")
        self.total_candidates = len(processed_candidates)  # Set for progress tracking
        
        # Wait for queue logic matches worker logic above
        
        try:
             # Wait for queue to be fully processed
             await queue.join()
             
             # Show final statistics
             self.console.print(f"\n[bold]Scan Statistics:[/bold]")
             self.console.print(f"  Processed: {self.processed_count}/{self.total_candidates}")
             self.console.print(f"  Live Findings: {self.success_count}")
             self.console.print(f"  Errors: {self.error_count}")
             
        except (KeyboardInterrupt, asyncio.CancelledError):
             self.console.print("\n[bold red][!] Stopping scan, cancelling workers...[/bold red]")
             # Cancel all workers
             for w in workers:
                 w.cancel()
             # Wait briefly for cancellation
             await asyncio.gather(*workers, return_exceptions=True)
             
             # Show partial statistics
             self.console.print(f"\n[bold yellow]Partial Statistics:[/bold yellow]")
             self.console.print(f"  Processed: {self.processed_count}/{self.total_candidates}")
             self.console.print(f"  Live Findings: {self.success_count}")
             self.console.print(f"  Errors: {self.error_count}")
        finally:
             # Cleanup
             if self.session:
                 await self.session.close()
                 # Allow time for underlying connector to close gracefully avoiding Windows selector errors
                 await asyncio.sleep(0.250)

        # --- PHASE 3: SUMMARY & REPORTING ---
        self.console.print("\n[bold]Phase 3: Analysis & Reporting[/bold]")
        
        # Sort by score descending
        sorted_findings = sorted(self.all_findings, key=lambda x: x.score, reverse=True)
        
        table = Table(title="Top High-Risk Findings", show_header=True, header_style="bold magenta", border_style="dim")
        table.add_column("Score", style="white", justify="right")
        table.add_column("Risk Categories", style="bold red")
        table.add_column("Domain", style="cyan")
        table.add_column("Status", style="green")
        
        shown_count = 0
        for res in sorted_findings:
            # Show top 25 findings that have at least some risk (score >= 3 or takeover)
            if res.score < 3 and not getattr(res, 'is_takeover', False):
                continue
                
            risk_str = ", ".join(res.risk_reasons) if res.risk_reasons else "-"
            table.add_row(str(res.score), risk_str, res.domain, str(res.http_status))
            shown_count += 1
            if shown_count >= 25:
                break
                
        if shown_count > 0:
            self.console.print(table)
        else:
            self.console.print("  [dim]No high-risk findings to summarize.[/dim]")

        # --- RECURSIVE ENUMERATION (if enabled) ---
        if self.recursive and len(self.all_findings) > 0:
            self.console.print("\n[bold magenta]Phase 4: Recursive Enumeration (2-level depth)[/bold magenta]")
            
            # Get all discovered subdomains
            discovered_subs = {f.domain for f in self.all_findings if f.status == "LIVE"}
            
            if discovered_subs:
                # Initialize recursive enumerator with passive sources
                self.recursive_enum = RecursiveEnumerator(
                    self.passive_sources,
                    max_depth=2,
                    verbose=self.verbose
                )
                
                # Run recursive enumeration
                recursive_subs = await self.recursive_enum.enumerate_recursive(discovered_subs, self.domain)
                
                # Add new discoveries to queue for processing
                new_from_recursive = recursive_subs - discovered_subs
                if new_from_recursive:
                    self.console.print(f"  [green]✓[/green] Found {len(new_from_recursive)} additional subdomains via recursion")
                    self.console.print(f"  [yellow]Adding to scan queue...[/yellow]")
                    
                    # Queue new subdomains for scanning
                    for sub in new_from_recursive:
                        if sub not in processed_candidates:
                            await queue.put(sub)
                            processed_candidates.add(sub)
                    
                    self.console.print(f"  [bold]Total queued:[/bold] {len(new_from_recursive)}")
                else:
                    self.console.print(f"  [dim]No additional subdomains found via recursion[/dim]")

        # --- NUCLEI VULNERABILITY SCANNING (if enabled) ---
        if self.nuclei_scanner and self.nuclei_scanner.is_available() and len(self.all_findings) > 0:
            self.console.print("\n[bold red]Phase 5: Nuclei Vulnerability Scanning[/bold red]")
            
            # Get all live domains
            live_domains = [f.domain for f in self.all_findings if f.status == "LIVE"]
            
            if live_domains:
                self.console.print(f"  Scanning {len(live_domains)} live subdomains for vulnerabilities...")
                nuclei_results = await self.nuclei_scanner.scan_targets(live_domains)
                
                if 'error' in nuclei_results:
                    self.console.print(f"  [red]✗[/red] {nuclei_results['error']}")
                elif nuclei_results['total_vulns'] > 0:
                    self.console.print(f"  [red]⚠[/red] Found {nuclei_results['total_vulns']} vulnerabilities!")
                    
                    # Show top vulnerabilities
                    for vuln in nuclei_results['vulnerabilities'][:10]:
                        severity_color = {
                            'critical': 'bold red',
                            'high': 'red',
                            'medium': 'yellow',
                            'low': 'dim'
                        }.get(vuln['severity'], 'white')
                        
                        self.console.print(f"    [{severity_color}]{vuln['severity'].upper()}[/{severity_color}] "
                                         f"{vuln['name']} on {vuln['host']}")
                else:
                    self.console.print(f"  [green]✓[/green] No vulnerabilities found")
            else:
                self.console.print(f"  [dim]No live domains to scan[/dim]")
        elif self.enable_nuclei and not self.nuclei_scanner.is_available():
            self.console.print("\n[yellow]⚠ Nuclei not installed. Skipping vulnerability scan.[/yellow]")
            self.console.print("  Install: https://github.com/projectdiscovery/nuclei")

        # --- EXPORT RESULTS ---
        if self.output_file:
            self.console.print(f"\n[bold]Exporting results to {self.output_file}...[/bold]")
            try:
                self.exporter.export(self.all_findings, self.output_file, self.output_format)
                self.console.print(f"[green]✓[/green] Exported {len(self.all_findings)} findings as {self.output_format.upper()}")
            except Exception as e:
                self.console.print(f"[red]✗[/red] Export failed: {str(e)}")

        self.console.print("\n[bold green]Scan Complete.[/bold green]")
