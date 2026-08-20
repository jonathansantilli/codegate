# Signed Content Feed

Detection content (knowledge-base entries, detection rules, override-phrase
lists, popular-package lists, known-bad indicators) can be delivered between
CodeGate releases as a single signed bundle. Scans never fetch anything;
only the explicit `codegate update-kb` / `update-rules` commands touch the
network, and every download is Ed25519-verified **before** it is parsed.

## Consumer side

```bash
codegate update-kb            # fetch, verify, install, activate
codegate update-kb --check    # compare installed vs published, install nothing
codegate update-kb --rollback # reactivate the previously installed version
```

Verified bundles are stored under `~/.codegate/content/<version>/` (the two
most recent versions are kept). Loaders prefer the active verified bundle
and fall back to the content bundled with the npm package on any problem —
a broken or tampered feed can never break scanning. Signatures are
re-verified on every load, not just at download time.

`codegate --version` reports the knowledge-base version in use; a feed KB
shows up as `feed-<content_version>` unless the bundle declares its own
`kb_schema_version`.

## Bundle format

One JSON document plus a detached signature:

- `codegate-content.json` — `{ schema_version: "1", content_version, released_at, kb_entries?, rules?, override_phrases?, popular_packages?, known_bad? }`
- `codegate-content.json.sig` — base64 Ed25519 signature over the exact bundle bytes

Every section is optional. Feed `kb_entries` are validated against the same
JSON schema as bundled entries; feed `rules` against the rule-pack schema.
An invalid entry disqualifies that section entirely (bundled content is the
fallback), never partially applies.

## Publisher side

Content lives in a dedicated repository:
**[jonathansantilli/codegate-content](https://github.com/jonathansantilli/codegate-content)**.
Its `bundle-src/` directory holds the bundle sources (what contributor PRs
edit), its `scripts/` build and sign the bundle, and its `CONTRIBUTING.md` /
`RELEASING.md` document the contribution and release flows. Bundles are
published as GitHub Release assets, and the default download URL here
(`src/content/content-updater.ts`, `DEFAULT_CONTENT_BASE_URL`) already points
at that repo's `releases/latest/download/`.

The Ed25519 signing key is held **offline by the repository owner** — never
in either repository or any CI secret. The matching public key is pinned in
`src/content/publisher-key.ts`; releases are signed locally by the owner
(`scripts/content-feed/sign-bundle.mjs`, also copied into the content repo)
before the bundle and its `.sig` are uploaded as release assets.

Key rotation means shipping a new CodeGate release with the new public key;
old builds will reject bundles signed by the new key, which is the intended
fail-closed behavior.

## Threat model notes

- Integrity and authenticity come from the signature, not the transport, so
  release-CDN redirects are acceptable; the URL must still be https.
- Download size is capped (8 MiB bundle, 4 KiB signature) and time-limited.
- A malicious mirror or a compromised download URL can at worst serve an old
  signed bundle (freshness is not enforced yet) or nothing; it cannot inject
  content.
