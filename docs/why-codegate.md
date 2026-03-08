# Why CodeGate Exists

CodeGate exists because AI coding tools now execute repository-controlled instructions, and that shifts trust from software binaries to project files that many users never review.

Security reports have repeatedly shown the same pattern:

- Risky behavior is treated as "documented behavior."
- Users install quickly and skip deep configuration review.
- Malicious or unsafe instructions can hide in normal-looking project files.

The result is a trust gap. Documentation alone does not protect users when execution surfaces are broad, defaults are permissive, and configuration changes are hard to see.

CodeGate is built to reduce that gap before execution starts.

## The Problem in Practical Terms

Before an AI tool runs, a repository can influence behavior through:

- MCP server definitions and remote endpoints
- Hooks, workflows, and command templates
- Rule/skill markdown that can carry hidden or coercive instructions
- Workspace settings and extension manifests
- Files that change over time after a user has already "trusted" a project

Most users do not have a clear, consolidated view of those surfaces at launch time.

## What CodeGate Tries to Do

CodeGate provides a pre-flight workflow that helps users:

- Discover execution and configuration surfaces
- Detect common high-risk patterns
- Understand risk before launching coding agents
- Apply reversible remediation where possible
- Recheck for trust drift just before tool launch (`codegate run`)

## What CodeGate Does Not Claim

CodeGate is not a guarantee of safety.

- It can produce false positives and false negatives.
- It does not replace secure engineering review.
- Optional deep analysis can require controlled interaction with remote metadata and local tools.
- New attack techniques can appear before signatures and heuristics are updated.

The goal is not perfect certainty. The goal is better visibility and better decisions before execution.

## Guiding Principles

- Inspect before trust.
- Prefer explicit user consent over silent execution.
- Keep high-risk operations explainable and reviewable.
- Treat "documented risk" as real risk when users are likely to miss it.
- Preserve operator control with backups, undo, and policy thresholds.
