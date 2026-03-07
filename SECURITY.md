# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| Latest `0.x` release | ✅ |
| Older `0.x` releases | ⚠️ Best effort |
| Unreleased branches | ❌ |

## How to report a vulnerability

Please report vulnerabilities privately first.

1. Do not open a public GitHub issue.
2. Email: `security@codegate.dev` with:
   - affected version
   - reproduction steps
   - impact assessment
   - proof-of-concept (if available)
3. We will acknowledge receipt within 5 business days and assign a tracking status.

## Disclosure Process

- We validate and triage the report.
- We coordinate a fix and release timeline.
- We publish an advisory after a fix is available (or mitigation guidance if no fix is immediately possible).

## Security Notes for Users

- Use `--format sarif` in CI to keep security findings visible in code-scanning workflows.
- Treat exit code `2` as a deployment/blocking condition in CI/CD.
- Use `codegate run <tool>` as a local pre-flight guard before launching AI coding tools; it blocks dangerous findings, can require confirmation for warning-only findings, and rechecks the scanned config surface before launch.
- Use `--deep` only when you explicitly want Layer 3 remote metadata analysis.
- Layer 3 requests are consent-gated per resource; skipped consent is reported for auditability.
- CodeGate does not execute untrusted MCP stdio command arrays during tool-description scanning.
- Use `codegate scan --reset-state` only when you intentionally want to clear MCP config change history stored at the resolved `scan_state_path` location.
