/**
 * Ed25519 public key of the CodeGate content publisher, PEM (SPKI) format.
 *
 * Deliberately null until the owner decides key custody and the content
 * repository location (see docs/content-feed.md). While null, the update
 * commands refuse to fetch and every loader uses only bundled content.
 * Generate a pair with scripts/content-feed/generate-keypair.mjs and paste
 * the public PEM here.
 */
export const CONTENT_PUBLISHER_PUBLIC_KEY_PEM: string | null = null;
