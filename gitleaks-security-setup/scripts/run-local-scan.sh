#!/bin/bash
#
# Local Gitleaks scan script
# Run from repository root to scan for secrets locally

# Check if Gitleaks is installed
if ! command -v gitleaks &> /dev/null; then
    echo "Gitleaks not found. Would you like to install it? (y/n)"
    read -r install_gitleaks
    
    if [[ $install_gitleaks == "y" || $install_gitleaks == "Y" ]]; then
        echo "Installing Gitleaks..."
        curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/install.sh | sh -s -- -b /usr/local/bin
    else
        echo "Please install Gitleaks first: https://github.com/gitleaks/gitleaks#installing"
        exit 1
    fi
fi

# Create output directory
mkdir -p gitleaks-scan-results

echo "==== Gitleaks Local Secret Scan ===="
echo "1. Quick scan (current state)"
echo "2. Full repository scan"
echo "3. Pre-commit scan (staged changes)"
echo "4. Scan specific path or file"
echo "5. Generate baseline"
echo "6. Exit"
echo ""
echo "Select an option (1-6): "
read -r option

case $option in
    1)
        echo "Running quick scan (current state)..."
        gitleaks detect \
            --source=. \
            --config=gitleaks-security-setup/configs/gitleaks.toml \
            --report-format=json \
            --report-path=gitleaks-scan-results/quick-scan.json \
            --no-git \
            --verbose
        
        # Check if any secrets were found
        if [ -s gitleaks-scan-results/quick-scan.json ]; then
            echo "⚠️ Potential secrets found! See gitleaks-scan-results/quick-scan.json for details."
            echo ""
            echo "Summary of findings:"
            jq -r '.[] | .RuleID' gitleaks-scan-results/quick-scan.json | sort | uniq -c
        else
            echo "✅ No secrets found in the current state!"
        fi
        ;;
    2)
        echo "Running full repository scan..."
        gitleaks detect \
            --source=. \
            --config=gitleaks-security-setup/configs/gitleaks.toml \
            --report-format=json \
            --report-path=gitleaks-scan-results/full-scan.json \
            --verbose
        
        # Check if any secrets were found
        if [ -s gitleaks-scan-results/full-scan.json ]; then
            echo "⚠️ Potential secrets found! See gitleaks-scan-results/full-scan.json for details."
            echo ""
            echo "Summary of findings by rule:"
            jq -r '.[] | .RuleID' gitleaks-scan-results/full-scan.json | sort | uniq -c
            echo ""
            echo "Summary of findings by file:"
            jq -r '.[] | .File' gitleaks-scan-results/full-scan.json | sort | uniq -c
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
        echo "$staged_files" > gitleaks-scan-results/staged-files.txt
        
        # Scan only staged files
        echo "Scanning staged files..."
        for file in $staged_files; do
            if [ -f "$file" ]; then
                echo "Scanning $file..."
                gitleaks detect \
                    --source="$file" \
                    --config=gitleaks-security-setup/configs/gitleaks.toml \
                    --report-format=json \
                    --report-path=gitleaks-scan-results/staged-scan.json \
                    --no-git \
                    --append-to-report
            fi
        done
        
        # Check if any secrets were found
        if [ -s gitleaks-scan-results/staged-scan.json ]; then
            echo "⚠️ Potential secrets found in your staged changes!"
            echo "Please remove these secrets before committing."
            echo ""
            echo "Summary of findings:"
            jq -r '.[] | "- \(.RuleID) in \(.File) (Line \(.StartLine))"' gitleaks-scan-results/staged-scan.json
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
        gitleaks detect \
            --source="$scan_path" \
            --config=gitleaks-security-setup/configs/gitleaks.toml \
            --report-format=json \
            --report-path="gitleaks-scan-results/path-scan-$(basename "$scan_path").json" \
            --no-git \
            --verbose
        
        # Check if any secrets were found
        if [ -s "gitleaks-scan-results/path-scan-$(basename "$scan_path").json" ]; then
            echo "⚠️ Potential secrets found in $scan_path! See gitleaks-scan-results/path-scan-$(basename "$scan_path").json for details."
            echo ""
            echo "Summary of findings:"
            jq -r '.[] | "- \(.RuleID) in \(.File) (Line \(.StartLine))"' "gitleaks-scan-results/path-scan-$(basename "$scan_path").json"
        else
            echo "✅ No secrets found in $scan_path!"
        fi
        ;;
    5)
        echo "Generating baseline..."
        gitleaks detect \
            --source=. \
            --config=gitleaks-security-setup/configs/gitleaks.toml \
            --report-format=json \
            --report-path=gitleaks-baseline.json \
            --no-git \
            --verbose
        
        # Check if any findings for baseline
        if [ -s gitleaks-baseline.json ]; then
            FINDINGS=$(jq '. | length' gitleaks-baseline.json)
            echo "Baseline generated with $FINDINGS findings."
            echo "You can use this baseline with the '--baseline-path=gitleaks-baseline.json' option in future scans."
        else
            echo "No findings for baseline. Created empty baseline file."
            echo "[]" > gitleaks-baseline.json
        fi
        ;;
    6)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid option. Exiting."
        exit 1
        ;;
esac
