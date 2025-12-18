#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
# Script to create main branch via GitHub API
# This bypasses the claude/ branch naming restriction

REPO_OWNER="willempoort"
REPO_NAME="netmonitor"
SOURCE_BRANCH="claude/review-server-monitoring-01TncykaQjqWd9Fn7kdu49gt"
TARGET_BRANCH="main"

echo "=========================================="
echo "Create Main Branch via GitHub API"
echo "=========================================="
echo ""

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo "❌ GitHub CLI (gh) is not installed"
    echo ""
    echo "Install with:"
    echo "  curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg"
    echo "  echo \"deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main\" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null"
    echo "  sudo apt update"
    echo "  sudo apt install gh"
    echo ""
    echo "Then authenticate with:"
    echo "  gh auth login"
    exit 1
fi

# Check if authenticated
if ! gh auth status &> /dev/null; then
    echo "❌ Not authenticated with GitHub"
    echo ""
    echo "Run: gh auth login"
    exit 1
fi

echo "✓ GitHub CLI is installed and authenticated"
echo ""

# Get the SHA of the latest commit on source branch
echo "Getting latest commit SHA from $SOURCE_BRANCH..."
COMMIT_SHA=$(gh api repos/$REPO_OWNER/$REPO_NAME/git/refs/heads/$SOURCE_BRANCH --jq '.object.sha')

if [ -z "$COMMIT_SHA" ]; then
    echo "❌ Could not get commit SHA from $SOURCE_BRANCH"
    exit 1
fi

echo "✓ Latest commit: $COMMIT_SHA"
echo ""

# Check if main branch already exists
echo "Checking if $TARGET_BRANCH already exists..."
if gh api repos/$REPO_OWNER/$REPO_NAME/git/refs/heads/$TARGET_BRANCH &> /dev/null; then
    echo "⚠️  $TARGET_BRANCH branch already exists!"
    echo ""
    read -p "Do you want to update it to point to $COMMIT_SHA? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Updating $TARGET_BRANCH branch..."
        gh api -X PATCH repos/$REPO_OWNER/$REPO_NAME/git/refs/heads/$TARGET_BRANCH \
            -f sha="$COMMIT_SHA" \
            -f force=true
        echo "✓ $TARGET_BRANCH branch updated!"
    else
        echo "Cancelled."
        exit 0
    fi
else
    # Create new main branch
    echo "Creating $TARGET_BRANCH branch..."
    gh api repos/$REPO_OWNER/$REPO_NAME/git/refs \
        -f ref="refs/heads/$TARGET_BRANCH" \
        -f sha="$COMMIT_SHA"

    echo "✓ $TARGET_BRANCH branch created!"
fi

echo ""
echo "=========================================="
echo "Setting $TARGET_BRANCH as default branch..."
echo "=========================================="
echo ""

gh api -X PATCH repos/$REPO_OWNER/$REPO_NAME \
    -f default_branch="$TARGET_BRANCH"

echo "✓ $TARGET_BRANCH is now the default branch!"
echo ""
echo "=========================================="
echo "Success!"
echo "=========================================="
echo ""
echo "You can now clone without specifying a branch:"
echo "  git clone https://github.com/$REPO_OWNER/$REPO_NAME"
echo ""
echo "Existing clones should switch to main:"
echo "  git fetch origin main"
echo "  git checkout main"
echo ""
