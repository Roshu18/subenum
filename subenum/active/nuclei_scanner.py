import subprocess
import os
from pathlib import Path
from ..security import SecurityValidator

class NucleiScanner:
    """
    Integrates Nuclei vulnerability scanner.
    Uses bundled Nuclei binary and templates from bin/ folder.
    """
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.nuclei_path = self._find_nuclei()
        self.templates_path = self._find_templates()
    
    def _find_nuclei(self) -> str:
        """Find bundled Nuclei binary."""
        # Check bundled binary first (in bin folder)
        tool_dir = Path(__file__).parent.parent.parent
        bundled_nuclei = tool_dir / 'bin' / 'nuclei.exe'
        
        if bundled_nuclei.exists():
            return str(bundled_nuclei)
        
        # Fallback to system nuclei
        try:
            result = subprocess.run(['nuclei', '-version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return 'nuclei'
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        return None
    
    def _find_templates(self) -> str:
        """Find bundled Nuclei templates."""
        tool_dir = Path(__file__).parent.parent.parent
        templates_dir = tool_dir / 'bin' / 'nuclei-templates'
        
        if templates_dir.exists():
            return str(templates_dir)
        
        return None
    
    def is_available(self) -> bool:
        """Check if Nuclei is installed and available."""
        return self.nuclei_path is not None
    
    async def scan_targets(self, targets: list, output_file: str = None) -> dict:
        """
        Scan targets with Nuclei.
        Returns dict with results.
        """
        if not self.is_available():
            return {'error': 'Nuclei not installed', 'vulnerabilities': []}
        
        # SECURITY: Validate all targets to prevent command injection
        validated_targets = SecurityValidator.validate_targets(targets)
        
        if not validated_targets:
            return {'error': 'No valid targets', 'vulnerabilities': []}
        
        # Write targets to temp file
        import tempfile
        # SECURITY: Use secure temp file creation
        fd, targets_file = tempfile.mkstemp(suffix='.txt', text=True)
        
        try:
            # Write validated targets only
            with os.fdopen(fd, 'w') as f:
                for target in validated_targets:
                    # SECURITY: Targets are already validated
                    f.write(f"https://{target}\n")
            
            # Build command
            cmd = [
                self.nuclei_path,
                '-l', targets_file,
                '-severity', 'low,medium,high,critical',
                '-silent',
                '-json'
            ]
            
            # Use bundled templates if available
            if self.templates_path:
                cmd.extend(['-t', self.templates_path])
            else:
                cmd.extend(['-t', 'cves/'])  # Default CVE templates
            
            if output_file:
                cmd.extend(['-o', output_file])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse results
            vulnerabilities = []
            if result.stdout:
                import json
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            vuln = json.loads(line)
                            vulnerabilities.append({
                                'host': vuln.get('host', ''),
                                'template': vuln.get('template-id', ''),
                                'name': vuln.get('info', {}).get('name', ''),
                                'severity': vuln.get('info', {}).get('severity', ''),
                            })
                        except json.JSONDecodeError:
                            pass
            
            return {
                'scanned': len(validated_targets),
                'vulnerabilities': vulnerabilities,
                'total_vulns': len(vulnerabilities)
            }
            
        except subprocess.TimeoutExpired:
            return {'error': 'Scan timeout', 'vulnerabilities': []}
        finally:
            # Cleanup temp file
            try:
                os.unlink(targets_file)
            except:
                pass
