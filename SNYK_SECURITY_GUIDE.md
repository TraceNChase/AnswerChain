# Snyk Security Setup Guide

## Overview
This repository has been configured with Snyk security scanning for the following technologies:
- Python (3.9, 3.10, 3.11, 3.12)
- Node.js
- PHP
- Scala (SBT 1.10.0)
- Infrastructure as Code

## Required Actions

### 1. Add Snyk Token to GitHub Secrets
- Go to repository Settings > Secrets and variables > Actions
- Add a new secret named `SNYK_TOKEN`
- Value: Your Snyk API token

### 2. Enable Snyk Security Scanning
- Go to repository Settings > Code security and analysis
- Enable "Dependency graph", "Dependabot alerts", and "Dependabot security updates"

### 3. Run Initial Scan
- Go to the "Actions" tab in your repository
- Select "Snyk Security Scan" from the workflows list
- Click "Run workflow" button
- Select the branch and click "Run workflow"

### 4. View Results
- After the scan completes, results will be visible in two places:
  - GitHub Security tab
  - Snyk.io dashboard

### 5. Local Scanning
- Install the Snyk CLI: `npm install -g snyk`
- Authenticate: `snyk auth`
- Run the local scan script: `./snyk-local-scan.sh`

## Files Created

1. `.github/workflows/snyk-security.yml` - Main workflow configuration
2. `.snyk` - Snyk policy and configuration
3. `snyk-local-scan.sh` - Script for local scanning
4. Test files (for verification only):
   - `test_vulnerable_python.py`
   - `test_package.json`
   - `test_terraform.tf`
   - `test_requirements.txt`

## Additional Resources
- [Snyk Documentation](https://docs.snyk.io/)
- [GitHub Security Documentation](https://docs.github.com/en/code-security)
