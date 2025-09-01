#!/bin/bash
#
# Bearer local security scan script
# Run from repository root to scan your project for data security issues

# Check if Bearer CLI is installed
if ! command -v bearer &> /dev/null; then
    echo "Bearer CLI not found. Would you like to install it? (y/n)"
    read -r install_bearer
    
    if [[ $install_bearer == "y" || $install_bearer == "Y" ]]; then
        echo "Installing Bearer CLI..."
        curl -sfL https://raw.githubusercontent.com/bearer/bearer/main/contrib/install.sh | sh
    else
        echo "Please install Bearer CLI first: https://docs.bearer.com/cli/install"
        exit 1
    fi
fi

# Create output directory
mkdir -p bearer-reports

# Display menu options
echo "==== Bearer Security Scan Options ===="
echo "1. Quick scan (entire repository)"
echo "2. Scan specific directory"
echo "3. Scan for specific data types"
echo "4. Generate comprehensive report"
echo "5. Exit"
echo ""
echo "Select an option (1-5): "
read -r option

timestamp=$(date +"%Y%m%d_%H%M%S")

case $option in
    1)
        echo "Running quick scan on entire repository..."
        bearer scan . \
            --format text,json,sarif \
            --output "bearer-reports/scan_$timestamp" \
            --log-level info
        
        echo "✓ Scan complete! Results saved to bearer-reports/scan_$timestamp"
        echo ""
        echo "Summary:"
        bearer report summary "bearer-reports/scan_$timestamp/report.json"
        ;;
    2)
        echo "Enter directory to scan (relative to repository root): "
        read -r scan_dir
        
        if [ -z "$scan_dir" ] || [ ! -d "$scan_dir" ]; then
            echo "Invalid directory. Exiting."
            exit 1
        fi
        
        echo "Running Bearer scan on directory: $scan_dir"
        bearer scan "$scan_dir" \
            --format text,json,sarif \
            --output "bearer-reports/scan_${scan_dir//\//_}_$timestamp" \
            --log-level info
        
        echo "✓ Scan complete! Results saved to bearer-reports/scan_${scan_dir//\//_}_$timestamp"
        ;;
    3)
        echo "Select data type to scan for:"
        echo "1. PII (Personal Identifiable Information)"
        echo "2. Credentials and secrets"
        echo "3. Financial data"
        echo "4. Health data"
        echo "5. All data types"
        read -r data_type
        
        case $data_type in
            1) dt_flag="--detector-types pii" ;;
            2) dt_flag="--detector-types credentials,keys,secrets" ;;
            3) dt_flag="--detector-types financial" ;;
            4) dt_flag="--detector-types health" ;;
            5) dt_flag="" ;;
            *) 
                echo "Invalid option. Using all data types."
                dt_flag=""
                ;;
        esac
        
        echo "Running Bearer scan for selected data types..."
        bearer scan . \
            $dt_flag \
            --format text,json,sarif \
            --output "bearer-reports/datatypes_$timestamp" \
            --log-level info
        
        echo "✓ Scan complete! Results saved to bearer-reports/datatypes_$timestamp"
        ;;
    4)
        echo "Generating comprehensive Bearer security report..."
        
        # Run full scan with all options
        bearer scan . \
            --format text,json,sarif,html \
            --output "bearer-reports/comprehensive_$timestamp" \
            --report-summary true \
            --log-level debug
        
        # Open HTML report if available
        if [ -f "bearer-reports/comprehensive_$timestamp/report.html" ]; then
            echo "✓ Comprehensive report generated!"
            echo ""
            echo "HTML report: bearer-reports/comprehensive_$timestamp/report.html"
            
            if command -v xdg-open &> /dev/null; then
                xdg-open "bearer-reports/comprehensive_$timestamp/report.html"
            elif command -v open &> /dev/null; then
                open "bearer-reports/comprehensive_$timestamp/report.html"
            else
                echo "Please open the HTML report manually."
            fi
        else
            echo "✓ Scan complete! Results saved to bearer-reports/comprehensive_$timestamp"
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
