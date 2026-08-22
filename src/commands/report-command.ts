import { hostname, platform, release, userInfo } from "node:os";
import { resolveFleetConfig, type FleetConfigDeps } from "../fleet/fleet-config.js";
import { resolveMachineId, type MachineIdentityDeps } from "../fleet/machine-identity.js";
import { sendReport, type SendReportDeps } from "../fleet/report-client.js";
import { buildReportPayload, type HashDeps, type HostFacts } from "../fleet/report-payload.js";
import type { InventorySummary } from "./inventory-command.js";

/**
 * Reports this machine's AI-tool inventory to a Guardian server.
 *
 * Everything it needs is already built: the inventory command produces the
 * data, and this only adds identity, hashes, and transport. It never changes
 * anything on the machine, and the server it talks to cannot ask it to.
 */

export interface ReportCommandDeps
  extends MachineIdentityDeps, FleetConfigDeps, SendReportDeps, HashDeps {
  collectInventory: () => InventorySummary;
  agentVersion?: string;
  now?: () => Date;
  hostFacts?: () => HostFacts;
}

export type ReportOutcome =
  | { status: "sent"; hostId: string; itemsAccepted: number; itemsHashed: number }
  | { status: "not-configured"; reason: string }
  | { status: "failed"; reason: string; retryable: boolean };

function defaultHostFacts(): HostFacts {
  let username: string | undefined;
  try {
    username = userInfo().username;
  } catch {
    // container users without a passwd entry: the hostname alone will do
  }

  return {
    hostname: hostname(),
    platform: platform(),
    osRelease: release(),
    ...(username ? { username } : {}),
  };
}

export async function runReport(deps: ReportCommandDeps): Promise<ReportOutcome> {
  const configured = resolveFleetConfig(deps);
  if (!configured.ok) {
    return { status: "not-configured", reason: configured.reason };
  }

  const payload = buildReportPayload(
    {
      machineId: resolveMachineId(deps),
      agentVersion: deps.agentVersion,
      host: (deps.hostFacts ?? defaultHostFacts)(),
      inventory: deps.collectInventory(),
      collectedAt: (deps.now ?? (() => new Date()))(),
    },
    deps,
  );

  const itemsHashed = payload.inventory.items.filter(
    (item) => (item as { sha256?: string }).sha256 !== undefined,
  ).length;

  const result = await sendReport(payload, configured.config, deps);

  return result.ok
    ? {
        status: "sent",
        hostId: result.hostId,
        itemsAccepted: result.itemsAccepted,
        itemsHashed,
      }
    : { status: "failed", reason: result.reason, retryable: result.retryable };
}
