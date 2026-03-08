export interface SignalProcessLike {
  on: (event: string, listener: () => void) => unknown;
  off: (event: string, listener: () => void) => unknown;
}

export interface RegisterSignalHandlersOptions {
  processLike?: SignalProcessLike;
  signals?: Array<"SIGINT" | "SIGTERM">;
  onSignal: (signal: "SIGINT" | "SIGTERM") => void;
}

export function registerSignalHandlers(options: RegisterSignalHandlersOptions): () => void {
  const processLike = options.processLike ?? process;
  const signals = options.signals ?? ["SIGINT", "SIGTERM"];
  const handlers = new Map<string, () => void>();

  for (const signal of signals) {
    const handler = () => {
      options.onSignal(signal);
    };
    handlers.set(signal, handler);
    processLike.on(signal, handler);
  }

  return () => {
    for (const [signal, handler] of handlers.entries()) {
      processLike.off(signal, handler);
    }
  };
}
