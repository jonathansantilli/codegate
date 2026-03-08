import { EventEmitter } from "node:events";
import { describe, expect, it } from "vitest";
import { registerSignalHandlers } from "../../src/runtime/signal-handlers";

class FakeProcess extends EventEmitter {
  on(event: string, listener: (...args: unknown[]) => void): this {
    return super.on(event, listener);
  }

  off(event: string, listener: (...args: unknown[]) => void): this {
    return super.off(event, listener);
  }
}

describe("task 19 signal handling", () => {
  it("invokes callback for SIGINT and SIGTERM", () => {
    const fakeProcess = new FakeProcess();
    const received: string[] = [];

    const cleanup = registerSignalHandlers({
      processLike: fakeProcess,
      onSignal: (signal) => {
        received.push(signal);
      },
    });

    fakeProcess.emit("SIGINT");
    fakeProcess.emit("SIGTERM");
    cleanup();

    expect(received).toEqual(["SIGINT", "SIGTERM"]);
  });

  it("cleanup removes registered handlers", () => {
    const fakeProcess = new FakeProcess();
    const before = fakeProcess.listenerCount("SIGINT");
    const cleanup = registerSignalHandlers({
      processLike: fakeProcess,
      onSignal: () => {},
    });

    expect(fakeProcess.listenerCount("SIGINT")).toBe(before + 1);
    cleanup();
    expect(fakeProcess.listenerCount("SIGINT")).toBe(before);
  });
});
