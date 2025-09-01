#!/bin/bash
#
# Local Grype scan script
# Run from repository root to scan your project locally

# Check if Grype is installed
if ! command -v grype &> /dev/null; then
    echo "Grype not found. Would you like to install it? (y/n)"
    read -r install_grype
    
    if [[ $install_grype == "y" || $install_grype == "Y" ]]; then
        echo "Installing Grype..."
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
    else
        echo "Please install Grype first: https://github.com/anchore/grype#installation"
        exit 1
    fi
fi

# Check if Syft is installed
if ! command -v syft &> /dev/null; then
    echo "Syft not found. Would you like to install it? (y/n)"
    read -r install_syft
    
    if [[ $install_syft == "y" || $install_syft == "Y" ]]; then
        echo "Installing Syft..."
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
    else
        echo "Syft installation skipped."
    fi
fi

echo "==== Grype Local Security Scan ===="
echo "1. Filesystem scan"
echo "2. Container image scan"
echo "3. Generate SBOM and scan"
echo "4. Comprehensive scan"
echo "5. Exit"
echo ""
echo "Select an option (1-5): "
read -r option

case $option in
    1)
        echo "Running filesystem scan..."
        grype dir:. -c grype-security-setup/configs/grype-config.yaml
        ;;
    2)
        echo "Enter container image name (e.g., alpine:latest): "
        read -r image_name
        if [[ -n "$image_name" ]]; then
            grype image:"$image_name" -c grype-security-setup/configs/grype-config.yaml
        else
            echo "No image name provided."
        fi
        ;;
    3)
        echo "Generating SBOM with Syft..."
        if command -v syft &> /dev/null; then
            syft dir:. -o cyclonedx-json > sbom.cyclonedx.json
            echo "Scanning SBOM..."
            grype sbom:sbom.cyclonedx.json -c grype-security-setup/configs/grype-config.yaml
        else
            echo "Syft not installed. Skipping SBOM generation."
        fi
        ;;
    4)
        echo "Running comprehensive scan..."
        echo "Scanning filesystem..."
        grype dir:. -c grype-security-setup/configs/grype-config.yaml
        
        if command -v syft &> /dev/null; then
            echo "Generating and scanning SBOM..."
            syft dir:. -o cyclonedx-json > sbom.cyclonedx.json
            grype sbom:sbom.cyclonedx.json -c grype-security-setup/configs/grype-config.yaml
        fi
        
        if [ -f "Dockerfile" ]; then
            echo "Building and scanning container..."
            docker build -t grype-local-scan:latest .
            grype image:grype-local-scan:latest -c grype-security-setup/configs/grype-config.yaml
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

echo "Scan complete!"
