# CodeGate Workflow Audit Parity Checklist

Use this checklist to track the workflow-audit detectors implemented in CodeGate and the backlog that remains.

## Wave A

- [x] `dangerous-triggers`
- [x] `excessive-permissions`
- [x] `known-vulnerable-actions`
- [x] `template-injection`
- [x] `unpinned-uses`
- [x] `artipacked`
- [x] `cache-poisoning`
- [x] `github-env`
- [x] `insecure-commands`
- [x] `self-hosted-runner`
- [x] `overprovisioned-secrets`
- [x] `secrets-outside-env`
- [x] `secrets-inherit`
- [x] `use-trusted-publishing`
- [x] `undocumented-permissions`

## Wave B

- [x] `archived-uses`
- [x] `stale-action-refs`
- [x] `forbidden-uses`
- [x] `ref-confusion`
- [x] `ref-version-mismatch`
- [x] `impostor-commit`
- [x] `unpinned-images`

## Wave C

- [x] `anonymous-definition`
- [x] `concurrency-limits`
- [x] `superfluous-actions`
- [x] `misfeature`
- [x] `obfuscation`
- [x] `unsound-condition`
- [x] `unsound-contains`

## Wave D

- [x] `dependabot-cooldown`
- [x] `dependabot-execution`

## Wave E

- [x] `hardcoded-container-credentials`
- [x] `unredacted-secrets`
- [x] `bot-conditions`

## Wave F (Planned)

- [ ] `workflow-call-boundary`
- [ ] `workflow-artifact-trust-chain`
- [ ] `workflow-oidc-untrusted-context`
- [x] `workflow-pr-target-checkout-head`
- [ ] `workflow-dynamic-matrix-injection`
- [ ] `workflow-secret-exfiltration`
- [ ] `dependabot-auto-merge`
- [ ] `workflow-local-action-mutation`

## Notes

- Checked items are implemented in CodeGate.
- Unchecked items remain in the backlog.
- The checklist is intentionally limited to CodeGate workflow-audit terminology.
