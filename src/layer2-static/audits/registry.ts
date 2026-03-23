import type { AuditPersona } from "../../config.js";
import type { AuditSelectionContext, RegisteredAudit } from "./types.js";

const PERSONA_ORDER: Record<AuditPersona, number> = {
  regular: 0,
  pedantic: 1,
  auditor: 2,
};

interface AuditSelectionContextWithDisable extends AuditSelectionContext {
  disabledAuditIds?: readonly string[];
}

function resolvePersona(input: AuditSelectionContext): AuditPersona {
  return input.persona ?? "regular";
}

function isPersonaAllowed(required: AuditPersona | undefined, current: AuditPersona): boolean {
  const requiredPersona = required ?? "regular";
  return PERSONA_ORDER[current] >= PERSONA_ORDER[requiredPersona];
}

function isRuntimeAllowed(
  onlineRequired: boolean | undefined,
  context: AuditSelectionContext,
): boolean {
  if (!onlineRequired) {
    return true;
  }

  const mode = context.runtimeMode ?? "offline";
  return mode === "online";
}

function isAuditDisabled(auditId: string, context: AuditSelectionContext): boolean {
  const disabledAuditIds = (context as AuditSelectionContextWithDisable).disabledAuditIds;
  return (disabledAuditIds ?? []).includes(auditId);
}

export function filterRegisteredAudits<TContext>(
  audits: Array<RegisteredAudit<TContext>>,
  context: AuditSelectionContext,
): Array<RegisteredAudit<TContext>> {
  const persona = resolvePersona(context);
  return audits.filter(
    (audit) =>
      !isAuditDisabled(audit.id, context) &&
      isPersonaAllowed(audit.minPersona, persona) &&
      isRuntimeAllowed(audit.onlineRequired, context),
  );
}

export type { RegisteredAudit } from "./types.js";
