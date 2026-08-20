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

## Publisher side (owner decisions pending)

Two decisions are required before the feed can go live; until then
`src/content/publisher-key.ts` is null and the update commands refuse to
fetch:

1. **Content repository location.** The default download URL points at
   GitHub Releases of `jonathansantilli/codegate-content`
   (`src/content/content-updater.ts`, `DEFAULT_CONTENT_BASE_URL`). Adjust if
   the content repo lives elsewhere.
2. **Signing-key custody.** Generate the keypair with
   `node scripts/content-feed/generate-keypair.mjs`. The private key must
   never enter this repository or its CI secrets; keep it in the content
   repo's release workflow (or offline) only. Paste the printed public PEM
   into `src/content/publisher-key.ts` and release CodeGate.

Publishing a content release:

```bash
node scripts/content-feed/sign-bundle.mjs codegate-content.json <private-key.pem>
# upload codegate-content.json and codegate-content.json.sig as release assets
```

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
