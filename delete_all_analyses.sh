#!/bin/bash

# --- Configuration ---
# Replace with your repository's owner and name.
OWNER="OWNER"
REPO="REPO"
# ---------------------

# 1. Check for dependencies
if ! command -v gh &> /dev/null; then
    echo "GitHub CLI 'gh' could not be found. Please install it to continue."
    echo "Installation instructions: https://cli.github.com/"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "'jq' could not be found. Please install it to continue."
    echo "Installation instructions: https://stedolan.github.io/jq/download/"
    exit 1
fi

# 2. Authenticate with GitHub CLI if needed
gh auth status > /dev/null 2>&1 || { echo "You are not logged into GitHub. Please run 'gh auth login'."; exit 1; }

echo "Fetching code scanning analyses for $OWNER/$REPO..."

# 3. Get all code scanning analysis IDs using the GitHub API
analysis_ids=$(gh api "repos/$OWNER/$REPO/code-scanning/analyses" --paginate -q '.[].id')

if [ -z "$analysis_ids" ]; then
  echo "No code scanning analyses found for $OWNER/$REPO."
  exit 0
fi

# 4. Loop through and delete each analysis
for id in $analysis_ids; do
  echo "Deleting analysis with ID: $id"
  if gh api \
    --method DELETE \
    -H "Accept: application/vnd.github+json" \
    "repos/$OWNER/$REPO/code-scanning/analyses/$id" --silent; then
    echo "Successfully deleted analysis ID: $id"
  else
    echo "Failed to delete analysis ID: $id"
  fi
done

echo "All code scanning analyses for $OWNER/$REPO have been deleted."