import type { AuditPersona, RuntimeMode } from "../../config.js";
import type { Finding } from "../../types/finding.js";

export interface AuditSelectionContext {
  persona?: AuditPersona;
  runtimeMode?: RuntimeMode;
}

export interface RegisteredAudit<TContext> {
  id: string;
  run: (context: TContext) => Finding[] | Promise<Finding[]>;
  minPersona?: AuditPersona;
  onlineRequired?: boolean;
}
