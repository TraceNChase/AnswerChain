#!/bin/bash
#
# Local TruffleHog scan script
# Run from repository root to scan for secrets locally

# Check if TruffleHog is installed
if ! command -v trufflehog &> /dev/null; then
    echo "TruffleHog not found. Would you like to install it? (y/n)"
    read -r install_trufflehog
    
    if [[ $install_trufflehog == "y" || $install_trufflehog == "Y" ]]; then
        echo "Installing TruffleHog..."
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
    else
        echo "Please install TruffleHog first: https://github.com/trufflesecurity/trufflehog#installation"
        exit 1
    fi
fi

# Create output directory
mkdir -p trufflehog-scan-results

echo "==== TruffleHog Local Secret Scan ===="
echo "1. Quick scan (last 50 commits)"
echo "2. Full repository scan"
echo "3. Pre-commit scan (staged changes)"
echo "4. Scan specific path or file"
echo "5. Exit"
echo ""
echo "Select an option (1-5): "
read -r option

case $option in
    1)
        echo "Running quick scan (last 50 commits)..."
        trufflehog git file://. \
            --since-commit HEAD~50 \
            --no-update \
            --exclude-paths trufflehog-security-setup/configs/trufflehog-exclude.txt \
            --json > trufflehog-scan-results/quick-scan.json
        
        # Check if any secrets were found
        if [ -s trufflehog-scan-results/quick-scan.json ]; then
            echo "⚠️ Potential secrets found! See trufflehog-scan-results/quick-scan.json for details."
            echo ""
            echo "Summary of findings:"
            cat trufflehog-scan-results/quick-scan.json | jq -r '.[] | "- \(.DetectorType) in \(.SourceMetadata.Data.Filesystem.file) (Line \(.SourceMetadata.Data.Filesystem.line_number))"' | sort | uniq -c
        else
            echo "✅ No secrets found in the last 50 commits!"
        fi
        ;;
    2)
        echo "Running full repository scan..."
        trufflehog git file://. \
            --no-update \
            --exclude-paths trufflehog-security-setup/configs/trufflehog-exclude.txt \
            --json > trufflehog-scan-results/full-scan.json
        
        # Check if any secrets were found
        if [ -s trufflehog-scan-results/full-scan.json ]; then
            echo "⚠️ Potential secrets found! See trufflehog-scan-results/full-scan.json for details."
            echo ""
            echo "Summary of findings:"
            cat trufflehog-scan-results/full-scan.json | jq -r '.[] | "- \(.DetectorType) in \(.SourceMetadata.Data.Filesystem.file) (Line \(.SourceMetadata.Data.Filesystem.line_number))"' | sort | uniq -c
        else
            echo "✅ No secrets found in the entire repository history!"
        fi
        ;;
    3)
        echo "Running pre-commit scan (staged changes)..."
        # Get list of staged files
        staged_files=$(git diff --cached --name-only)
        
        if [ -z "$staged_files" ]; then
            echo "No staged changes found. Stage your changes with 'git add' first."
            exit 0
        fi
        
        # Create temporary file with list of staged files
        echo "$staged_files" > trufflehog-scan-results/staged-files.txt
        
        # Scan only staged files
        trufflehog filesystem \
            --exclude-paths trufflehog-security-setup/configs/trufflehog-exclude.txt \
            --only-verified \
            --json \
            --include-paths trufflehog-scan-results/staged-files.txt \
            . > trufflehog-scan-results/staged-scan.json
        
        # Check if any secrets were found
        if [ -s trufflehog-scan-results/staged-scan.json ]; then
            echo "⚠️ Potential secrets found in your staged changes!"
            echo "Please remove these secrets before committing."
            echo ""
            echo "Summary of findings:"
            cat trufflehog-scan-results/staged-scan.json | jq -r '.[] | "- \(.DetectorType) in \(.SourceMetadata.Data.Filesystem.file) (Line \(.SourceMetadata.Data.Filesystem.line_number))"'
            exit 1
        else
            echo "✅ No secrets found in staged changes!"
        fi
        ;;
    4)
        echo "Enter path to scan (relative to repository root): "
        read -r scan_path
        
        if [ -z "$scan_path" ]; then
            echo "No path provided. Exiting."
            exit 1
        fi
        
        if [ ! -e "$scan_path" ]; then
            echo "Path not found: $scan_path"
            exit 1
        fi
        
        echo "Scanning $scan_path for secrets..."
        trufflehog filesystem \
            --exclude-paths trufflehog-security-setup/configs/trufflehog-exclude.txt \
            --json \
            "$scan_path" > "trufflehog-scan-results/path-scan-$(basename "$scan_path").json"
        
        # Check if any secrets were found
        if [ -s "trufflehog-scan-results/path-scan-$(basename "$scan_path").json" ]; then
            echo "⚠️ Potential secrets found in $scan_path! See trufflehog-scan-results/path-scan-$(basename "$scan_path").json for details."
            echo ""
            echo "Summary of findings:"
            cat "trufflehog-scan-results/path-scan-$(basename "$scan_path").json" | jq -r '.[] | "- \(.DetectorType) in \(.SourceMetadata.Data.Filesystem.file) (Line \(.SourceMetadata.Data.Filesystem.line_number))"' | sort | uniq -c
        else
            echo "✅ No secrets found in $scan_path!"
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
