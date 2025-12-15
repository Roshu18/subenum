import asyncio
import click
from subenum.runner import Runner

@click.command()
@click.option('-d', '--domain', required=True, help='Target domain (e.g. example.com)')
@click.option('-c', '--concurrency', default=10, type=click.IntRange(1, 20), help='Number of concurrent workers (Default: 10, Max: 20)')
@click.option('--safe', is_flag=True, help='Enable Safe/Quick Scan (Uses smaller wordlist)')
@click.option('-w', '--wordlist', default=None, help='Path to custom wordlist file')
@click.option('-q', '--quiet', is_flag=True, help='Disable verbose output (verbose is default)')
@click.option('-o', '--output', default=None, help='Output file path (e.g. results.json)')
@click.option('-f', '--format', type=click.Choice(['json', 'csv', 'txt'], case_sensitive=False), default='json', help='Output format (Default: json)')
@click.option('--recursive', is_flag=True, help='Enable recursive subdomain enumeration (2-level depth)')
@click.option('--axfr', is_flag=True, help='Attempt DNS zone transfer (AXFR)')
@click.option('--ports', is_flag=True, help='Scan common web ports (80,443,8080,8443,3000,8000,8888,9000)')
@click.option('--nuclei', is_flag=True, help='Run Nuclei vulnerability scanner on findings')
def main(domain, concurrency, safe, wordlist, quiet, output, format, recursive, axfr, ports, nuclei):
    """
    High-Speed Subdomain Enumeration Tool
    """
    # Verbose is True by default, False if --quiet is used
    verbose = not quiet
    # deep_scan is True by default unless --safe is used
    runner = Runner(domain, concurrency, deep_scan=not safe, wordlist=wordlist, verbose=verbose, 
                    output_file=output, output_format=format, recursive=recursive, axfr=axfr,
                    enable_ports=ports, enable_nuclei=nuclei)
    try:
        import sys
        import warnings
        if sys.platform == 'win32':
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        asyncio.run(runner.start())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")

if __name__ == '__main__':
    main()
