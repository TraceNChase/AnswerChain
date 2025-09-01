#!/bin/bash
#
# Local OSV Scanner script
# Run from repository root to scan your project locally

# Check if OSV Scanner is installed
if ! command -v osv-scanner &> /dev/null; then
    echo "OSV Scanner not found. Would you like to install it? (y/n)"
    read -r install_osv
    
    if [[ $install_osv == "y" || $install_osv == "Y" ]]; then
        echo "Installing OSV Scanner..."
        if command -v go &> /dev/null; then
            go install github.com/google/osv-scanner/cmd/osv-scanner@latest
            export PATH=$PATH:$(go env GOPATH)/bin
        else
            echo "Go is required to install OSV Scanner."
            echo "Please install Go first: https://golang.org/doc/install"
            exit 1
        fi
    else
        echo "Please install OSV Scanner first: https://github.com/google/osv-scanner"
        exit 1
    fi
fi

# Create output directory
mkdir -p osv-scan-results

echo "==== OSV Scanner Local Security Scan ===="
echo "1. Basic scan"
echo "2. Recursive scan (all subdirectories)"
echo "3. Lockfile scan (only dependency files)"
echo "4. SBOM generation and scan"
echo "5. Exit"
echo ""
echo "Select an option (1-5): "
read -r option

case $option in
    1)
        echo "Running basic scan..."
        osv-scanner --config osv-security-setup/configs/osv-scanner.toml . > osv-scan-results/basic-scan.txt
        ;;
    2)
        echo "Running recursive scan..."
        osv-scanner --recursive --config osv-security-setup/configs/osv-scanner.toml . > osv-scan-results/recursive-scan.txt
        ;;
    3)
        echo "Running lockfile scan..."
        osv-scanner --lockfile **/go.mod --lockfile **/package-lock.json --lockfile **/Cargo.lock --lockfile **/requirements.txt --lockfile **/poetry.lock --config osv-security-setup/configs/osv-scanner.toml > osv-scan-results/lockfile-scan.txt
        ;;
    4)
        echo "Generating SBOM and scanning..."
        if command -v cyclonedx-gomod &> /dev/null; then
            mkdir -p sbom
            cyclonedx-gomod mod -output sbom/cyclonedx.json
            osv-scanner --sbom sbom/cyclonedx.json > osv-scan-results/sbom-scan.txt
        else
            echo "cyclonedx-gomod not found. Would you like to install it? (y/n)"
            read -r install_cyclonedx
            
            if [[ $install_cyclonedx == "y" || $install_cyclonedx == "Y" ]]; then
                go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
                export PATH=$PATH:$(go env GOPATH)/bin
                
                mkdir -p sbom
                cyclonedx-gomod mod -output sbom/cyclonedx.json
                osv-scanner --sbom sbom/cyclonedx.json > osv-scan-results/sbom-scan.txt
            else
                echo "Skipping SBOM generation and scan."
            fi
        fi
        ;;
    5)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid option. Exiting."
        exit 1
        ;;
esac

echo "Scan complete! Results saved to osv-scan-results directory."

# Check if there are any vulnerabilities
if grep -q "No vulnerabilities found" osv-scan-results/*.txt; then
    echo "✅ No vulnerabilities found!"
else
    echo "⚠️ Vulnerabilities found! Please check the scan results."
fi
