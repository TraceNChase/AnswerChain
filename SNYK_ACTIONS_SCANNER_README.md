# Snyk GitHub Actions Scanner

This repository is configured with Snyk GitHub Actions Scanner to detect security issues in GitHub Actions workflow files.

## What is Snyk GitHub Actions Scanner?

Snyk GitHub Actions Scanner is a specialized security tool that analyzes GitHub Actions workflow files for:

- Use of non-pinned actions (supply chain risks)
- Excessive GitHub token permissions
- Command injection vulnerabilities
- Insecure downloading of dependencies
- Credentials exposure
- Self-hosted runner security issues
- And more...

## How It's Configured

The scanner is integrated in three ways:

1. **GitHub Actions Workflow**: Automatically scans workflow files on pushes, PRs, and scheduled runs
2. **Local Scanning Script**: For manual scanning during development
3. **Git Pre-commit Hook**: To catch issues before they're committed

## Setup Requirements

### For GitHub Actions Workflow

1. **Snyk API Token** (Optional but recommended)
   - Sign up at [Snyk.io](https://snyk.io)
   - Get your API token from Account Settings
   - Add it as a GitHub Secret named `SNYK_TOKEN`

### For Local Scanning

1. **Node.js and npm**
2. **Snyk GitHub Actions Scanner**
   ```bash
   npm install -g @snyk/github-actions-scanner
