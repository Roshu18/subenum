"""
Auto-installer for Nuclei vulnerability scanner.
Downloads Nuclei binary and templates to tool directory.
"""

import os
import sys
import zipfile
import tarfile
import platform
import requests
from pathlib import Path

class NucleiInstaller:
    """Automatically downloads and installs Nuclei."""
    
    def __init__(self, install_dir=None):
        if install_dir is None:
            # Install in tool directory
            self.install_dir = Path(__file__).parent.parent / 'bin'
        else:
            self.install_dir = Path(install_dir)
        
        self.install_dir.mkdir(parents=True, exist_ok=True)
        self.nuclei_path = self.install_dir / ('nuclei.exe' if sys.platform == 'win32' else 'nuclei')
        self.templates_dir = self.install_dir / 'nuclei-templates'
    
    def is_installed(self) -> bool:
        """Check if Nuclei is already installed."""
        return self.nuclei_path.exists() and self.templates_dir.exists()
    
    def get_download_url(self) -> str:
        """Get the correct download URL for the current platform."""
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        # Map platform to Nuclei release naming
        if system == 'windows':
            if 'amd64' in machine or 'x86_64' in machine:
                return 'https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.6_windows_amd64.zip'
            else:
                return 'https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.6_windows_386.zip'
        elif system == 'linux':
            if 'aarch64' in machine or 'arm64' in machine:
                return 'https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.6_linux_arm64.zip'
            else:
                return 'https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.6_linux_amd64.zip'
        elif system == 'darwin':  # macOS
            if 'arm64' in machine:
                return 'https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.6_macOS_arm64.zip'
            else:
                return 'https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.6_macOS_amd64.zip'
        else:
            raise OSError(f"Unsupported platform: {system}")
    
    def download_file(self, url: str, dest: Path, desc: str = "Downloading"):
        """Download a file with progress."""
        print(f"  {desc}...")
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        
        with open(dest, 'wb') as f:
            if total_size == 0:
                f.write(response.content)
            else:
                downloaded = 0
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        percent = (downloaded / total_size) * 100
                        print(f"\r  Progress: {percent:.1f}%", end='', flush=True)
                print()  # New line after progress
    
    def install_nuclei(self):
        """Download and install Nuclei binary."""
        print("[*] Installing Nuclei...")
        
        url = self.get_download_url()
        zip_path = self.install_dir / 'nuclei.zip'
        
        try:
            # Download
            self.download_file(url, zip_path, "Downloading Nuclei binary")
            
            # Extract
            print("  Extracting...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(self.install_dir)
            
            # Make executable on Unix
            if sys.platform != 'win32':
                os.chmod(self.nuclei_path, 0o755)
            
            # Cleanup
            zip_path.unlink()
            
            print("  ✓ Nuclei installed successfully")
            
        except Exception as e:
            print(f"  ✗ Failed to install Nuclei: {e}")
            raise
    
    def install_templates(self):
        """Download and install Nuclei templates."""
        print("[*] Installing Nuclei templates...")
        
        url = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"
        zip_path = self.install_dir / 'templates.zip'
        
        try:
            # Download
            self.download_file(url, zip_path, "Downloading templates (~100MB)")
            
            # Extract
            print("  Extracting templates...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(self.install_dir)
            
            # Rename extracted folder
            extracted_dir = self.install_dir / 'nuclei-templates-main'
            if extracted_dir.exists():
                if self.templates_dir.exists():
                    import shutil
                    shutil.rmtree(self.templates_dir)
                extracted_dir.rename(self.templates_dir)
            
            # Cleanup
            zip_path.unlink()
            
            print("  ✓ Templates installed successfully")
            
        except Exception as e:
            print(f"  ✗ Failed to install templates: {e}")
            raise
    
    def install(self):
        """Install Nuclei and templates."""
        if self.is_installed():
            print("[✓] Nuclei is already installed")
            return True
        
        print("\n" + "="*60)
        print("  NUCLEI AUTO-INSTALLER")
        print("="*60)
        print("Nuclei will be installed to:", self.install_dir)
        print()
        
        try:
            # Install Nuclei binary
            if not self.nuclei_path.exists():
                self.install_nuclei()
            
            # Install templates
            if not self.templates_dir.exists():
                self.install_templates()
            
            print("\n[✓] Installation complete!")
            print(f"Nuclei path: {self.nuclei_path}")
            print(f"Templates: {self.templates_dir}")
            print("="*60 + "\n")
            
            return True
            
        except Exception as e:
            print(f"\n[✗] Installation failed: {e}")
            print("You can manually install Nuclei from: https://github.com/projectdiscovery/nuclei")
            return False
    
    def get_nuclei_path(self) -> str:
        """Get the path to the Nuclei binary."""
        if self.is_installed():
            return str(self.nuclei_path)
        return None
    
    def get_templates_path(self) -> str:
        """Get the path to the templates directory."""
        if self.is_installed():
            return str(self.templates_dir)
        return None


if __name__ == '__main__':
    # Test installer
    installer = NucleiInstaller()
    installer.install()
