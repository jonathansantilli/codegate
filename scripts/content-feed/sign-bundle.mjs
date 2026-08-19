#!/usr/bin/env node
// Signs a content bundle: writes <bundle>.sig (base64 Ed25519 signature
// over the exact bundle bytes).
//
// Usage: node scripts/content-feed/sign-bundle.mjs <bundle.json> <private-key.pem>
import { createPrivateKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const [bundlePath, keyPath] = process.argv.slice(2);
if (!bundlePath || !keyPath) {
  console.error("Usage: sign-bundle.mjs <bundle.json> <private-key.pem>");
  process.exit(1);
}

const bundleBytes = readFileSync(bundlePath);
const privateKey = createPrivateKey(readFileSync(keyPath, "utf8"));
const signature = sign(null, bundleBytes, privateKey).toString("base64");

writeFileSync(`${bundlePath}.sig`, `${signature}\n`, "utf8");
console.log(`Signature written to ${bundlePath}.sig`);
