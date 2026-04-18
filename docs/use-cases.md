# fintech-security-hardening — Use Case Examples

---

## Use Case 1: Add the Full Security Pipeline to Any Repo

Create `.github/workflows/security.yml` in your repo:

```yaml
name: Security

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

# Copy the full devsecops-pipeline.yml from this repo
# OR reference it as a reusable workflow if you've set it up that way:
jobs:
  security:
    uses: YOUR_ORG/fintech-security-hardening/.github/workflows/devsecops-pipeline.yml@main
```

**Result:** 5 security gates run on every PR. Results appear in GitHub Security tab. Merge blocked on any failure.

---

## Use Case 2: Validate Your Kubernetes Manifests Locally Before Pushing

```bash
# Install OPA
brew install opa    # macOS
# or: curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64

# Run validation against your manifests
./scripts/validate-k8s-policies.sh ./your-k8s-manifests/

# Example output:
# [OK]   ./apps/payments-api/base/deployment.yaml
# [FAIL] ./apps/auth-service/base/deployment.yaml
#   - Container 'auth-service' must set runAsNonRoot: true
#   - Container 'auth-service' must define a livenessProbe
```

Fix violations before pushing — no CI roundtrip needed.

---

## Use Case 3: Install the Pre-Commit Secret Scanner

```bash
# Install gitleaks
brew install gitleaks   # macOS

# Install the pre-commit hook
cp scripts/check-secrets.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Now every git commit scans staged files automatically
git add my-file.py
git commit -m "add config"
# [info] Scanning staged files for secrets...
# [BLOCKED] Secret detected: AWS_SECRET_ACCESS_KEY in my-file.py line 12
```

If it's a false positive (e.g. a test fixture), suppress inline:
```python
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # gitleaks:allow
```

---

## Use Case 4: Add a Custom OPA Policy

**Situation:** Your org requires every Deployment to have a specific label (`team`).

Add to `policies/opa/k8s-security.rego`:

```rego
# Require team label on every Deployment
deny[msg] {
  input.kind == "Deployment"
  not input.metadata.labels.team
  msg := sprintf(
    "Deployment '%s' must have a 'team' label for cost attribution",
    [input.metadata.name]
  )
}
```

No code changes needed — just add the rule and the CI pipeline picks it up automatically.

---

## Use Case 5: Document a CVE Exception in .trivyignore

**Situation:** Trivy flags CVE-2024-12345 but no fix exists yet and you've mitigated it at the WAF.

```bash
# .trivyignore — NEVER add a CVE without all three fields
CVE-2024-12345  # reason: no upstream fix; mitigated by WAF rule blocking path traversal. Expires: 2026-07-01. Approved by: security-team@company.com
```

The CI pipeline respects this file. The expiry date is enforced by a cron job that removes stale entries — if you haven't renewed it, it gets re-surfaced automatically.

---

## Use Case 6: Tune Severity Threshold to Reduce Noise

By default the pipeline blocks on `HIGH,CRITICAL`. For a dev/internal tool where you want to allow HIGH but still block CRITICAL:

```yaml
# .github/workflows/devsecops-pipeline.yml
env:
  SEVERITY_THRESHOLD: "CRITICAL"   # was HIGH,CRITICAL
```

For a PCI-scoped payment service where you want to fail even on MEDIUM:
```yaml
env:
  SEVERITY_THRESHOLD: "MEDIUM,HIGH,CRITICAL"
```

The single `env:` block at the top of the workflow controls all three scan jobs simultaneously.

---

## Use Case 7: Fix a Common OPA Policy Violation

**Violation:** `Container 'api' must set readOnlyRootFilesystem: true`

**Fix in your deployment.yaml:**
```yaml
containers:
  - name: api
    securityContext:
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      capabilities:
        drop: ["ALL"]
    # If your app writes temp files, mount a writable emptyDir:
    volumeMounts:
      - name: tmp
        mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

This is the correct pattern — not disabling the policy, but making your container actually stateless.
