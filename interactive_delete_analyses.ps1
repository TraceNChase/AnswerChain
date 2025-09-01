<#
.SYNOPSIS
Interactively deletes all code scanning analyses from a specified GitHub repository.
#>

# --- Script to Interactively Delete Code Scanning Analyses (PowerShell Version) ---

# 1. Check for dependencies
Write-Host "Checking for dependencies..."
$ghExists = (Get-Command gh -ErrorAction SilentlyContinue)
$jqExists = (Get-Command jq -ErrorAction SilentlyContinue)

if (-not $ghExists) {
    Write-Error "GitHub CLI 'gh' could not be found. Please install it to continue."
    Write-Host "Installation instructions: https://cli.github.com/"
    exit 1
}

if (-not $jqExists) {
    Write-Error "'jq' could not be found. Please install it to continue."
    Write-Host "Installation instructions: https://stedolan.github.io/jq/download/"
    exit 1
}
Write-Host "Dependencies found."
Write-Host ""

# 2. Authenticate with GitHub CLI
Write-Host "Checking GitHub authentication status..."
gh auth status -h github.com *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Error "You are not logged into the GitHub CLI. Please run 'gh auth login' and grant the 'repo' scope."
    exit 1
}
Write-Host "Authentication successful."
Write-Host ""

# 3. Get repository details from user
$OWNER = Read-Host -Prompt "Enter the repository owner (e.g., 'microsoft')"
$REPO = Read-Host -Prompt "Enter the repository name (e.g., 'vscode')"

if ([string]::IsNullOrEmpty($OWNER) -or [string]::IsNullOrEmpty($REPO)) {
    Write-Error "Owner and repository name cannot be empty."
    exit 1
}

Write-Host ""
Write-Host "Fetching code scanning analyses for '$OWNER/$REPO'..."

# 4. Fetch analysis IDs
try {
    $analysis_ids = gh api "repos/$OWNER/$REPO/code-scanning/analyses" --paginate | jq '.[].id'
} catch {
    Write-Error "Failed to fetch analyses for '$OWNER/$REPO'."
    Write-Error "This could be due to a typo, or your token may lack 'repo' or 'security_events' permissions."
    Write-Error "API Error details: $($_.Exception.Message)"
    exit 1
}

if ($null -eq $analysis_ids -or $analysis_ids.Length -eq 0) {
  Write-Host "Result: No code scanning analyses were found for '$OWNER/$REPO'."
  exit 0
}

# 5. Perform a Dry Run
Write-Host "Found the following analysis IDs:"
$analysis_ids | ForEach-Object { Write-Host $_ }
$id_count = ($analysis_ids | Measure-Object).Count
Write-Host "Total analyses found: $id_count"
Write-Host ""

$confirm = Read-Host -Prompt "Do you want to proceed with deleting these analyses? (y/N)"
if ($confirm.ToLower() -ne 'y') {
    Write-Host "Aborted. No analyses were deleted."
    exit 0
}

# 6. Loop through and delete each analysis
Write-Host ""
Write-Host "Starting deletion process..."
$deleted_count = 0
$failed_count = 0
foreach ($id in $analysis_ids) {
  Write-Host -NoNewline "Deleting analysis ID: $id... "
  gh api --method DELETE "repos/$OWNER/$REPO/code-scanning/analyses/$id" --silent
  if ($LASTEXITCODE -eq 0) {
    Write-Host "SUCCESS" -ForegroundColor Green
    $deleted_count++
  } else {
    Write-Host "FAILED" -ForegroundColor Red
    $failed_count++
  }
}

# 7. Final Report
Write-Host ""
Write-Host "--- Deletion Complete ---"
Write-Host "Successfully deleted: $deleted_count"
Write-Host "Failed to delete:   $failed_count"
Write-Host "-------------------------"

if ($failed_count -gt 0) {
    Write-Warning "Some deletions failed. This may be due to permission issues. Please ensure your token has the necessary scopes ('repo', 'security_events')."
}