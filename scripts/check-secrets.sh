#!/usr/bin/env bash
# Pre-commit hook: scan staged files for secrets before they hit the repo.
# Install: cp scripts/check-secrets.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
set -euo pipefail

if ! command -v gitleaks &>/dev/null; then
  echo "[warn] gitleaks not installed — skipping secret scan"
  echo "       Install: brew install gitleaks"
  exit 0
fi

echo "[info] Scanning staged files for secrets..."
gitleaks protect --staged --redact --verbose

if [ $? -ne 0 ]; then
  echo ""
  echo "[BLOCKED] Secret detected in staged files."
  echo "          Remove the secret, rotate any exposed credentials, and try again."
  echo "          If this is a false positive, add an inline comment: # gitleaks:allow"
  exit 1
fi

echo "[ok] No secrets detected."
