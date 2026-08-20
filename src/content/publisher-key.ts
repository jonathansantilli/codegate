/**
 * Ed25519 public key of the CodeGate content publisher, PEM (SPKI) format.
 *
 * Verifies bundles published by the content-feed repository
 * (see docs/content-feed.md). The matching private key is held offline by
 * the repository owner — it exists in no repository and no CI secret.
 * Rotation means pasting a new public PEM here and shipping a release;
 * older builds reject bundles signed by the new key, which is the intended
 * fail-closed behavior. If this is ever set to null, the update commands
 * refuse to fetch and every loader uses only bundled content.
 */
export const CONTENT_PUBLISHER_PUBLIC_KEY_PEM: string | null = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9q23ANqtLZROQGIHu0+LU9m3Rav/ud4CsVB+7Iow27g=
-----END PUBLIC KEY-----
`;
