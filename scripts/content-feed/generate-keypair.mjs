#!/usr/bin/env node
// Generates the Ed25519 keypair for signing CodeGate content bundles.
// The private key must live OUTSIDE this repository (see docs/content-feed.md).
import { generateKeyPairSync } from "node:crypto";
import { writeFileSync } from "node:fs";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");

const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
const publicPem = publicKey.export({ type: "spki", format: "pem" });

const privatePath = process.argv[2] ?? "codegate-content-signing-key.pem";
writeFileSync(privatePath, privatePem, { mode: 0o600 });

console.log(`Private key written to ${privatePath} (keep it out of any repository).`);
console.log("");
console.log("Public key — paste into src/content/publisher-key.ts:");
console.log("");
console.log(publicPem);
