# Known-Bad Indicator Format

CodeGate matches scanned content against a list of known-malicious indicators.
A match produces a CRITICAL `known-malicious-content` finding (exit code 2),
except for fingerprint indicators, which escalate the matching finding to
CRITICAL instead of adding a new one.

## Sources

Indicators are merged from two places, in both cases without network access at
scan time:

1. **The signed content feed** — the `known_bad` block of the verified content
   bundle (see [content-feed.md](content-feed.md)). This is the shared,
   community-maintained list.
2. **`~/.codegate/known-bad.json`** — a local, user-maintained file with the
   same shape as the `known_bad` block. Use it for private indicators or
   before a feed release picks up a submission. The file is trusted like the
   global config; scanned projects can never supply indicators.

A missing, unparseable, or partially malformed file degrades to the valid
subset — indicator problems never break scanning.

## Shape

```json
{
  "file_sha256": ["sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"],
  "package_names": ["evil-mcp-server", "@bad-scope/backdoor"],
  "url_patterns": ["evil.example.com", "paste.example.net/raw/abc123"],
  "finding_fingerprints": [
    "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
  ]
}
```

All keys are optional string arrays. Entries that do not validate are ignored
individually.

| Key                    | Matched against                                                                     | Semantics                                                     |
| ---------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `file_sha256`          | SHA-256 of each scanned file's UTF-8 text content                                   | Exact hash match; the `sha256:` prefix is optional            |
| `package_names`        | Package names launched by MCP server configs (`npx`, `pnpx`, `bunx`, `uvx`, `pipx`) | Exact name match, case-insensitive, version specifier ignored |
| `url_patterns`         | `http(s)://` URLs found in scanned file content                                     | Case-insensitive substring of the URL                         |
| `finding_fingerprints` | The `fingerprint` field of findings in the JSON report                              | Exact match; the matching finding is escalated to CRITICAL    |

## Contributing indicators

Shared indicators live in the content-feed repository:
[jonathansantilli/codegate-content](https://github.com/jonathansantilli/codegate-content).
Open a PR there editing `bundle-src/known-bad.json` (this same shape), and
include in the description:

- where the malicious content was observed (registry link, repo, campaign
  write-up), and
- enough context to verify the entry independently.

See that repo's `CONTRIBUTING.md` for details. Maintainers verify every entry
before it ships; indicators reach users only through signed feed releases,
and nothing is fetched at scan time. For private indicators — or before a
feed release picks up a submission — use the local
`~/.codegate/known-bad.json` described above.
