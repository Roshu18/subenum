#!/bin/bash
# Nuclei Setup Script for Linux
# Downloads Nuclei binary and templates

echo "============================================================"
echo "  NUCLEI SETUP - Bundling Nuclei with Tool (Linux)"
echo "============================================================"
echo ""

# Create bin directory
mkdir -p bin
echo "[+] Created bin directory"

# Detect architecture
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/v3.3.6/nuclei_3.3.6_linux_amd64.zip"
elif [ "$ARCH" = "aarch64" ]; then
    NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/v3.3.6/nuclei_3.3.6_linux_arm64.zip"
else
    echo "[ERROR] Unsupported architecture: $ARCH"
    exit 1
fi

# Download Nuclei
echo "[*] Downloading Nuclei binary..."
wget -q --show-progress "$NUCLEI_URL" -O bin/nuclei.zip
echo "  [OK] Downloaded Nuclei"

# Extract
echo "[*] Extracting Nuclei..."
unzip -q bin/nuclei.zip -d bin/
rm bin/nuclei.zip
chmod +x bin/nuclei
echo "  [OK] Extracted nuclei binary"

# Download Templates
echo "[*] Downloading Nuclei templates (~100MB, this may take a while)..."
wget -q --show-progress https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip -O bin/templates.zip
echo "  [OK] Downloaded templates"

# Extract templates
echo "[*] Extracting templates..."
unzip -q bin/templates.zip -d bin/
mv bin/nuclei-templates-main bin/nuclei-templates
rm bin/templates.zip
echo "  [OK] Extracted templates"

echo ""
echo "============================================================"
echo "[SUCCESS] Setup Complete!"
echo ""
echo "Nuclei binary: bin/nuclei"
echo "Templates: bin/nuclei-templates/"
echo ""
echo "You can now use --nuclei flag for vulnerability scanning!"
echo "============================================================"
