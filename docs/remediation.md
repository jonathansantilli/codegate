# Remediation Guide

CodeGate remediation converts findings into concrete file changes with backups and undo support.

## Modes

| Mode | Command | Behavior |
|---|---|---|
| Interactive remediation | `codegate scan . --remediate` | Plans fixes and applies remediation actions |
| Auto-fix safe | `codegate scan . --fix-safe` | Applies only CRITICAL safe actions |
| Dry run | `codegate scan . --remediate --dry-run` | Produces remediation plan without writing files |
| Patch | `codegate scan . --remediate --patch` | Generates unified patch output |

## Patch Output

- Default (TTY): writes `codegate-fixes.patch` in scan target.
- With `--output <path>`: writes patch to custom path.
- Non-TTY with no `--output`: prints patch to stdout.

## Backup and Undo

When remediation writes files, CodeGate creates a session under:

`<project>/.codegate-backup/<session-id>/`

Each session includes:
- backup copies of modified files
- `.manifest.json` with SHA-256 hashes

Undo restores the latest valid session:

```bash
codegate undo
```

If manifest hashes do not match backup content, restore is refused.

## Safety Notes

- Remediation only applies fixable findings.
- Strict JSON files are never modified with comment insertion.
- Backups are verified before restore to prevent tampered rollback content.
