import { resolve } from "node:path";
import {
  listBackupSessions,
  restoreBackupSession,
  type RestoreBackupSessionResult,
} from "../layer4-remediation/backup-manager.js";

export interface UndoLatestSessionInput {
  projectRoot: string;
}

export function undoLatestSession(input: UndoLatestSessionInput): RestoreBackupSessionResult {
  const projectRoot = resolve(input.projectRoot);
  const sessions = listBackupSessions(projectRoot);

  if (sessions.length === 0) {
    throw new Error("No backup sessions found.");
  }

  const latestSession = sessions[0] as string;
  return restoreBackupSession({
    projectRoot,
    sessionId: latestSession,
  });
}
