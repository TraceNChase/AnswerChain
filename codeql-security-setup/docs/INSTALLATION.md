# CodeQL Security Installation Guide

## Installation Steps

1. **Review the Files**
   All CodeQL security files are contained in the `codeql-security-setup` directory to avoid conflicts with existing files.

2. **Move Workflow File**
   To activate the CodeQL scanning:
   ```bash
   mkdir -p .github/workflows/
   cp codeql-security-setup/.github/workflows/codeql-analysis.yml .github/workflows/
