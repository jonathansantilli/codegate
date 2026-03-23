import { describe, expect, it } from "vitest";
import {
  filterRegisteredAudits,
  type RegisteredAudit,
} from "../../src/layer2-static/audits/registry";

interface TestAuditContext {
  value: number;
}

function makeAudits(): Array<RegisteredAudit<TestAuditContext>> {
  return [
    {
      id: "regular-audit",
      run: () => [],
      minPersona: "regular",
    },
    {
      id: "pedantic-audit",
      run: () => [],
      minPersona: "pedantic",
    },
    {
      id: "online-audit",
      run: () => [],
      minPersona: "regular",
      onlineRequired: true,
    },
  ];
}

describe("audit registry filtering", () => {
  it("filters audits by persona", () => {
    const regular = filterRegisteredAudits(makeAudits(), {
      persona: "regular",
      runtimeMode: "offline",
    });
    const auditor = filterRegisteredAudits(makeAudits(), {
      persona: "auditor",
      runtimeMode: "offline",
    });

    expect(regular.map((audit) => audit.id)).toEqual(["regular-audit"]);
    expect(auditor.map((audit) => audit.id)).toEqual(["regular-audit", "pedantic-audit"]);
  });

  it("filters online-required audits by runtime mode", () => {
    const online = filterRegisteredAudits(makeAudits(), {
      persona: "auditor",
      runtimeMode: "online",
    });
    const offline = filterRegisteredAudits(makeAudits(), {
      persona: "auditor",
      runtimeMode: "offline",
    });
    const onlineNoAudits = filterRegisteredAudits(makeAudits(), {
      persona: "auditor",
      runtimeMode: "online-no-audits",
    });

    expect(online.some((audit) => audit.id === "online-audit")).toBe(true);
    expect(offline.some((audit) => audit.id === "online-audit")).toBe(false);
    expect(onlineNoAudits.some((audit) => audit.id === "online-audit")).toBe(false);
  });
});
