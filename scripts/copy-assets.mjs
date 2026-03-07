import { cpSync, existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const mappings = [
  ["src/knowledge-base", "dist/knowledge-base"],
  ["src/layer3-dynamic/prompt-templates", "dist/layer3-dynamic/prompt-templates"],
];

for (const [sourceRelative, destinationRelative] of mappings) {
  const source = resolve(root, sourceRelative);
  const destination = resolve(root, destinationRelative);

  if (!existsSync(source)) {
    throw new Error(`Missing source asset directory: ${sourceRelative}`);
  }

  mkdirSync(dirname(destination), { recursive: true });
  cpSync(source, destination, { recursive: true });
}

