#!/usr/bin/env bash
# Validate all Kubernetes manifests against OPA security policies.
# Usage: ./scripts/validate-k8s-policies.sh [path-to-manifests]
set -euo pipefail

MANIFEST_DIR=${1:-.}
POLICY_FILE="policies/opa/k8s-security.rego"
VIOLATIONS=0

if ! command -v opa &>/dev/null; then
  echo "[error] OPA not installed. Install: https://www.openpolicyagent.org/docs/latest/#running-opa"
  exit 1
fi

echo "==> Validating manifests in: $MANIFEST_DIR"
echo "    Policy: $POLICY_FILE"
echo ""

while IFS= read -r -d '' manifest; do
  kind=$(grep "^kind:" "$manifest" 2>/dev/null | head -1 | awk '{print $2}')
  if [[ "$kind" != "Deployment" ]]; then
    continue
  fi

  result=$(opa eval \
    --data "$POLICY_FILE" \
    --input "$manifest" \
    --format raw \
    "data.kubernetes.security.deny" 2>/dev/null)

  if [[ "$result" != "[]" ]]; then
    echo "[FAIL] $manifest"
    echo "$result" | python3 -c "import sys,json; [print('  -', v) for v in json.load(sys.stdin)]"
    VIOLATIONS=$((VIOLATIONS + 1))
  else
    echo "[OK]   $manifest"
  fi
done < <(find "$MANIFEST_DIR" -name "*.yaml" -not -path "*/.git/*" -print0)

echo ""
if [ "$VIOLATIONS" -gt 0 ]; then
  echo "==> $VIOLATIONS policy violation(s) found. Fix before merging."
  exit 1
else
  echo "==> All manifests pass security policies."
fi
