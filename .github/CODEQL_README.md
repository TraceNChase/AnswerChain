# CodeQL: Advanced Setup

- Workflow: `.github/workflows/codeql.yml`
- Config: `.github/codeql/config.yml`
- Custom queries: `.github/codeql/queries/`
- Compliance: `.github/codeql/compliance/`
- Reporting: `.github/codeql/tools/sarif_summary.py`

Triggers: Push/PR to `main`/`master`, weekly schedule, manual dispatch.
Permissions: `contents:read`, `security-events:write`.
Scoping: use `paths`/`paths-ignore` in the config; SARIF filter reinforces exclusions.
Compiled languages: switch to manual build if needed and replace Autobuild.
