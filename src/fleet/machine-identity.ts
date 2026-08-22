import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * The machine's identity on a Guardian server.
 *
 * Generated once and kept in the codegate home directory, because nothing the
 * operating system offers is both stable and unique: hostnames repeat across
 * an organization ("MacBook-Pro.local") and change when a laptop is renamed,
 * and hardware ids are absent or spoofable depending on the platform. A file
 * we wrote ourselves is neither, and losing it only costs one duplicate host.
 */

const ID_FILE = "machine-id";
const MAX_ID_LENGTH = 200;
const VALID_ID = /^[A-Za-z0-9._-]+$/;
/** Readable and writable by the owner only: it authenticates nothing, but it correlates everything. */
const FILE_MODE = 0o600;
const DIR_MODE = 0o700;

export interface MachineIdentityDeps {
  homeDir?: () => string;
  generateId?: () => string;
}

export function machineIdPath(deps: MachineIdentityDeps = {}): string {
  const home = deps.homeDir ? deps.homeDir() : homedir();
  return join(home, ".codegate", ID_FILE);
}

function isUsable(value: string): boolean {
  return value.length > 0 && value.length <= MAX_ID_LENGTH && VALID_ID.test(value);
}

/**
 * Returns this machine's id, creating and persisting one on first use.
 *
 * A corrupt or empty file is replaced rather than repaired: the identity is
 * already lost at that point, and refusing to report would be worse than
 * appearing on the server as a new machine.
 */
export function resolveMachineId(deps: MachineIdentityDeps = {}): string {
  const path = machineIdPath(deps);

  if (existsSync(path)) {
    try {
      const existing = readFileSync(path, "utf8").trim();
      if (isUsable(existing)) {
        return existing;
      }
    } catch {
      // fall through and mint a new one
    }
  }

  const generated = (deps.generateId ?? randomUUID)();
  const id = isUsable(generated.trim()) ? generated.trim() : randomUUID();

  mkdirSync(join(path, ".."), { recursive: true, mode: DIR_MODE });
  writeFileSync(path, `${id}\n`, { encoding: "utf8", mode: FILE_MODE });

  return id;
}
