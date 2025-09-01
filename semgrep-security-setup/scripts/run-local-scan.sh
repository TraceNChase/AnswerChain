#!/bin/bash
#
# Local Semgrep scan script
# Run from repository root to scan your project for security issues

# Check if Semgrep is installed
if ! command -v semgrep &> /dev/null; then
    echo "Semgrep not found. Would you like to install it? (y/n)"
    read -r install_semgrep
    
    if [[ $install_semgrep == "y" || $install_semgrep == "Y" ]]; then
        echo "Installing Semgrep..."
        pip install semgrep
    else
        echo "Please install Semgrep first: pip install semgrep"
        exit 1
    fi
fi

# Create output directory
mkdir -p semgrep-scan-results

echo "==== Semgrep Local Security Scan ===="
echo "1. Quick scan (auto rules)"
echo "2. Full security scan"
echo "3. Scan for specific rule types"
echo "4. Scan specific path or file"
echo "5. Generate Semgrep scan report"
echo "6. Exit"
echo ""
echo "Select an option (1-6): "
read -r option

case $option in
    1)
        echo "Running quick scan with auto rules..."
        semgrep scan \
            --config=auto \
            --output=semgrep-scan-results/quick-scan.txt
        
        # Check if any issues were found
        if [ -s "semgrep-scan-results/quick-scan.txt" ]; then
            echo "⚠️ Potential issues found! See semgrep-scan-results/quick-scan.txt for details."
        else
            echo "✅ No issues found!"
        fi
        ;;
    2)
        echo "Running full security scan..."
        semgrep scan \
            --config=p/default \
            --config=p/security-audit \
            --config=p/owasp-top-ten \
            --config=p/cwe-top-25 \
            --config=semgrep-security-setup/configs/semgrep-rules.yaml \
            --json > semgrep-scan-results/full-scan.json \
            --output=semgrep-scan-results/full-scan.txt
        
        # Check if any issues were found
        if [ -s "semgrep-scan-results/full-scan.txt" ]; then
            echo "⚠️ Potential issues found! See semgrep-scan-results/full-scan.txt for details."
            echo ""
            echo "Summary of findings by rule:"
            jq -r '.results | group_by(.check_id) | map({rule: .[0].check_id, count: length}) | sort_by(.count) | reverse | .[] | "\(.count) findings: \(.rule)"' semgrep-scan-results/full-scan.json
        else
            echo "✅ No issues found!"
        fi
        ;;
    3)
        echo "What type of issues would you like to scan for?"
        echo "1. Security issues"
        echo "2. Code quality issues"
        echo "3. OWASP Top 10"
        echo "4. Supply chain issues"
        echo "5. CWE Top 25"
        read -r rule_type
        
        case $rule_type in
            1)
                ruleset="p/security-audit"
                ;;
            2)
                ruleset="p/ci"
                ;;
            3)
                ruleset="p/owasp-top-ten"
                ;;
            4)
                ruleset="p/supply-chain"
                ;;
            5)
                ruleset="p/cwe-top-25"
                ;;
            *)
                echo "Invalid option. Using security audit ruleset."
                ruleset="p/security-audit"
                ;;
        esac
        
        echo "Running scan with $ruleset..."
        semgrep scan \
            --config=$ruleset \
            --output=semgrep-scan-results/specific-scan.txt
        
        # Check if any issues were found
        if [ -s "semgrep-scan-results/specific-scan.txt" ]; then
            echo "⚠️ Potential issues found! See semgrep-scan-results/specific-scan.txt for details."
        else
            echo "✅ No issues found!"
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
        
        echo "Scanning $scan_path for security issues..."
        semgrep scan \
            --config=p/security-audit \
            --config=semgrep-security-setup/configs/semgrep-rules.yaml \
            --output="semgrep-scan-results/path-scan-$(basename "$scan_path").txt" \
            "$scan_path"
        
        # Check if any issues were found
        if [ -s "semgrep-scan-results/path-scan-$(basename "$scan_path").txt" ]; then
            echo "⚠️ Potential issues found! See semgrep-scan-results/path-scan-$(basename "$scan_path").txt for details."
        else
            echo "✅ No issues found in $scan_path!"
        fi
        ;;
    5)
        echo "Generating comprehensive scan report..."
        
        # Run scan with report generation
        semgrep scan \
            --config=p/default \
            --config=p/security-audit \
            --config=p/owasp-top-ten \
            --config=semgrep-security-setup/configs/semgrep-rules.yaml \
            --json > semgrep-scan-results/report.json \
            --output=semgrep-scan-results/report.txt
        
        # Create HTML report
        if [ -s "semgrep-scan-results/report.json" ]; then
            echo "Creating HTML report..."
            
            # Simple HTML report creation
            cat > semgrep-scan-results/report.html << 'HTML_EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Semgrep Scan Results</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 { color: #2d68c4; }
        h2 { color: #2b4283; }
        .error { color: #cc0000; font-weight: bold; }
        .warning { color: #f0ad4e; font-weight: bold; }
        .info { color: #5bc0de; }
        .finding {
            border: 1px solid #ddd;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .code {
            font-family: monospace;
            background: #f5f5f5;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 3px;
            overflow: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 8px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #f2f5fa;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
    </style>
</head>
<body>
HTML_EOF

            # Add report header
            echo "<h1>Semgrep Security Scan Report</h1>" >> semgrep-scan-results/report.html
            echo "<p>Scan date: $(date)</p>" >> semgrep-scan-results/report.html
            
            # Check if we have findings
            findings=$(jq '.results | length' semgrep-scan-results/report.json)
            echo "<p>Total findings: $findings</p>" >> semgrep-scan-results/report.html
            
            if [ "$findings" -gt 0 ]; then
                # Add severity summary
                echo "<h2>Findings by Severity</h2>" >> semgrep-scan-results/report.html
                echo "<table>" >> semgrep-scan-results/report.html
                echo "<tr><th>Severity</th><th>Count</th></tr>" >> semgrep-scan-results/report.html
                
                # Count by severity
                error_count=$(jq '[.results[] | select(.extra.severity == "ERROR" or .extra.severity == "CRITICAL")] | length' semgrep-scan-results/report.json)
                warning_count=$(jq '[.results[] | select(.extra.severity == "WARNING" or .extra.severity == "HIGH")] | length' semgrep-scan-results/report.json)
                info_count=$(jq '[.results[] | select(.extra.severity == "INFO" or .extra.severity == "MEDIUM")] | length' semgrep-scan-results/report.json)
                other_count=$(jq '[.results[] | select(.extra.severity != "ERROR" and .extra.severity != "CRITICAL" and .extra.severity != "WARNING" and .extra.severity != "HIGH" and .extra.severity != "INFO" and .extra.severity != "MEDIUM")] | length' semgrep-scan-results/report.json)
                
                echo "<tr><td class='error'>ERROR/CRITICAL</td><td>$error_count</td></tr>" >> semgrep-scan-results/report.html
                echo "<tr><td class='warning'>WARNING/HIGH</td><td>$warning_count</td></tr>" >> semgrep-scan-results/report.html
                echo "<tr><td class='info'>INFO/MEDIUM</td><td>$info_count</td></tr>" >> semgrep-scan-results/report.html
                echo "<tr><td>Other</td><td>$other_count</td></tr>" >> semgrep-scan-results/report.html
                echo "</table>" >> semgrep-scan-results/report.html
                
                # Add findings by file
                echo "<h2>Findings by File</h2>" >> semgrep-scan-results/report.html
                echo "<table>" >> semgrep-scan-results/report.html
                echo "<tr><th>File</th><th>Issues</th></tr>" >> semgrep-scan-results/report.html
                
                jq -r '.results | group_by(.path) | map({file: .[0].path, count: length}) | sort_by(.count) | reverse | .[] | "<tr><td>\(.file)</td><td>\(.count)</td></tr>"' semgrep-scan-results/report.json >> semgrep-scan-results/report.html
                
                echo "</table>" >> semgrep-scan-results/report.html
                
                # Add detailed findings
                echo "<h2>Detailed Findings</h2>" >> semgrep-scan-results/report.html
                
                jq -r '.results[] | "<div class=\"finding\"><h3>\(.check_id)</h3><p><strong>Severity:</strong> <span class=\"\(.extra.severity | ascii_downcase)\">\(.extra.severity)</span></p><p><strong>File:</strong> \(.path) (lines \(.start.line)-\(.end.line))</p><p><strong>Message:</strong> \(.extra.message)</p><div class=\"code\">\(.extra.lines)</div></div>"' semgrep-scan-results/report.json >> semgrep-scan-results/report.html
                
            else
                echo "<h2>No issues found!</h2>" >> semgrep-scan-results/report.html
                echo "<p>Great job! Semgrep did not detect any issues in your codebase.</p>" >> semgrep-scan-results/report.html
            fi
            
            # Close HTML
            echo "</body></html>" >> semgrep-scan-results/report.html
            
            echo "✅ Report generated! See semgrep-scan-results/report.html"
        else
            echo "⚠️ No report data generated."
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
