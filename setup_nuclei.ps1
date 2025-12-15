# Nuclei Setup Script
# Downloads Nuclei binary and templates to bin folder

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  NUCLEI SETUP - Bundling Nuclei with Tool" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Create bin directory
$binDir = "bin"
if (!(Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir | Out-Null
    Write-Host "[+] Created bin directory" -ForegroundColor Green
}

# Download Nuclei
Write-Host "[*] Downloading Nuclei binary..." -ForegroundColor Yellow
$nucleiUrl = "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.6/nuclei_3.3.6_windows_amd64.zip"
$nucleiZip = "$binDir\nuclei.zip"

try {
    Invoke-WebRequest -Uri $nucleiUrl -OutFile $nucleiZip -UseBasicParsing
    Write-Host "  [OK] Downloaded Nuclei" -ForegroundColor Green
    
    # Extract
    Write-Host "[*] Extracting Nuclei..." -ForegroundColor Yellow
    Expand-Archive -Path $nucleiZip -DestinationPath $binDir -Force
    Remove-Item $nucleiZip
    Write-Host "  [OK] Extracted Nuclei.exe" -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] Failed to download Nuclei: $_" -ForegroundColor Red
    exit 1
}

# Download Templates
Write-Host "[*] Downloading Nuclei templates (~100MB, this may take a while)..." -ForegroundColor Yellow
$templatesUrl = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"
$templatesZip = "$binDir\templates.zip"

try {
    Invoke-WebRequest -Uri $templatesUrl -OutFile $templatesZip -UseBasicParsing
    Write-Host "  [OK] Downloaded templates" -ForegroundColor Green
    
    # Extract
    Write-Host "[*] Extracting templates..." -ForegroundColor Yellow
    Expand-Archive -Path $templatesZip -DestinationPath $binDir -Force
    
    # Rename folder
    if (Test-Path "$binDir\nuclei-templates") {
        Remove-Item "$binDir\nuclei-templates" -Recurse -Force
    }
    Rename-Item "$binDir\nuclei-templates-main" "nuclei-templates"
    Remove-Item $templatesZip
    
    Write-Host "  [OK] Extracted templates" -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] Failed to download templates: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "[SUCCESS] Setup Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Nuclei binary: $binDir\nuclei.exe" -ForegroundColor White
Write-Host "Templates: $binDir\nuclei-templates\" -ForegroundColor White
Write-Host ""
Write-Host "You can now use --nuclei flag for vulnerability scanning!" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
