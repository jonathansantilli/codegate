# Workflow Audit Real-Case Corpus

This document tracks real public workflow/dependabot examples used to validate workflow-audit detections locally.

## Local Corpus

Root:

- `test-fixtures/workflow-audits/real-cases/`
- `test-fixtures/workflow-audits/real-cases/index.json`

Each fixture is commit-pinned to keep source provenance stable.

## Cases

1. `RC-01-bot-conditions`

- Expected rule: `bot-conditions`
- Source: <https://github.com/Significant-Gravitas/AutoGPT/blob/0f67e45d05c855077236f739ca3a02fa95fc7e96/.github/workflows/claude-dependabot.yml>
- Local file: `test-fixtures/workflow-audits/real-cases/RC-01-bot-conditions/.github/workflows/claude-dependabot.yml`

2. `RC-02-obfuscation`

- Expected rule: `workflow-obfuscation`
- Source: <https://github.com/electron/electron/blob/6df6ec5f094f1546b5510c47aa478b2e19187f88/.github/workflows/pipeline-electron-lint.yml>
- Local file: `test-fixtures/workflow-audits/real-cases/RC-02-obfuscation/.github/workflows/pipeline-electron-lint.yml`

3. `RC-03-concurrency-limits`

- Expected rule: `workflow-concurrency-limits`
- Source: <https://github.com/electricitymaps/electricitymaps-contrib/blob/7d22bea77bd73a9bcc8c7e6fe78a973713ba8637/.github/workflows/label.yml>
- Local file: `test-fixtures/workflow-audits/real-cases/RC-03-concurrency-limits/.github/workflows/label.yml`

4. `RC-04-dependabot-execution`

- Expected rule: `dependabot-execution`
- Source: <https://github.com/RoleModel/rolemodel_rails/blob/83f8c13518afd1137405b81fc4723e202f833368/lib/generators/rolemodel/github/templates/dependabot.yml>
- Local file: `test-fixtures/workflow-audits/real-cases/RC-04-dependabot-execution/.github/dependabot.yml`

5. `RC-05-workflow-pr-target-checkout-head`

- Expected rule: `workflow-pr-target-checkout-head`
- Source: <https://github.com/antiwork/gumroad/blob/000969060793173ff7501038e4104794a5f842b1/.github/workflows/tests.yml>
- Local file: `test-fixtures/workflow-audits/real-cases/RC-05-workflow-pr-target-checkout-head/.github/workflows/tests.yml`

6. `RC-06-workflow-artifact-trust-chain`

- Expected rule: `workflow-artifact-trust-chain`
- Source: <https://github.com/facebook/react/blob/3e1abcc8d7083a13adf4774feb0d67ecbe4a2bc4/.github/workflows/runtime_build_and_test.yml>
- Local file: `test-fixtures/workflow-audits/real-cases/RC-06-workflow-artifact-trust-chain/.github/workflows/runtime_build_and_test.yml`

7. `RC-07-workflow-call-boundary`

- Expected rule: `workflow-call-boundary`
- Source: <https://github.com/valkey-io/valkey/blob/543a6b83dffff9d35da046ad2067a94b60cf3f38/.github/workflows/daily.yml>
- Local file: `test-fixtures/workflow-audits/real-cases/RC-07-workflow-call-boundary/.github/workflows/daily.yml`

8. `RC-08-workflow-secret-exfiltration`

- Expected rule: `workflow-secret-exfiltration`
- Source: <https://github.com/r-dbi/odbc/blob/02f4a32cacde3b24168cf4d28a18279e22c4939f/.github/workflows/db-pro.yaml>
- Local file: `test-fixtures/workflow-audits/real-cases/RC-08-workflow-secret-exfiltration/.github/workflows/db-pro.yaml`

9. `RC-09-workflow-oidc-untrusted-context`

- Expected rule: `workflow-oidc-untrusted-context`
- Source: <https://github.com/grafana/grafana/blob/2131a63ca06a161abcc1f46ff0352ca2ce3b06ca/.github/workflows/frontend-lint.yml>
- Local file: `test-fixtures/workflow-audits/real-cases/RC-09-workflow-oidc-untrusted-context/.github/workflows/frontend-lint.yml`

10. `RC-10-dependabot-auto-merge`

- Expected rule: `dependabot-auto-merge`
- Source: <https://github.com/bflad/go-module-two/blob/b34d6ff790df1dec533198da4be2f9857199d725/.github/workflows/dependabot-auto-merge.yml>
- Local file: `test-fixtures/workflow-audits/real-cases/RC-10-dependabot-auto-merge/.github/workflows/dependabot-auto-merge.yml`

11. `RC-11-workflow-local-action-mutation`

- Expected rule: `workflow-local-action-mutation`
- Source: <https://github.com/grafana/grafana/blob/2131a63ca06a161abcc1f46ff0352ca2ce3b06ca/.github/workflows/frontend-lint.yml>
- Local file: `test-fixtures/workflow-audits/real-cases/RC-11-workflow-local-action-mutation/.github/workflows/frontend-lint.yml`

## Validation

Run targeted test:

```bash
npm test -- tests/layer2/workflow-real-cases.test.ts
```

Run CLI manually:

```bash
codegate scan test-fixtures/workflow-audits/real-cases/RC-06-workflow-artifact-trust-chain --workflow-audits --no-tui --format json
```
