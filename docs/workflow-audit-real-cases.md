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

## Validation

Run targeted test:

```bash
npm test -- tests/layer2/workflow-real-cases.test.ts
```

Run CLI manually:

```bash
codegate scan test-fixtures/workflow-audits/real-cases/RC-02-obfuscation --workflow-audits --no-tui --format json
```
