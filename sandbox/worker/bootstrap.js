// Installed before every program. It captures the engine's print function in
// a closure and removes it from the global object, so only this code can send
// messages to the host, and every message carries a per-run nonce the program
// cannot read. The program sees its input, connectors and console.
(function (print, nonce, consoleLimit) {
  "use strict";
  const stringify = JSON.stringify;
  const send = (message) => print(nonce + stringify(message));
  const pending = new Map();
  let nextId = 0;
  const lines = [];
  let used = 0;
  let overflowed = false;

  const text = (value) => {
    if (typeof value === "string") return value;
    try {
      const json = stringify(value);
      return json === undefined ? String(value) : json;
    } catch (e) {
      return String(value);
    }
  };
  const log = (...values) => {
    if (overflowed) return;
    const line = values.map(text).join(" ");
    used += line.length + 1;
    if (used > consoleLimit) {
      overflowed = true;
      send({ type: "failed", failure: { kind: "limit", message: "console output exceeds " + consoleLimit + " bytes" } });
      return;
    }
    lines.push(line);
  };
  const console = Object.freeze({ log, info: log, warn: log, error: log, debug: log });

  const call = (proxy, tool, args) =>
    new Promise((resolve, reject) => {
      nextId += 1;
      const id = nextId;
      pending.set(id, { resolve, reject });
      send({ type: "call", id, proxy, tool, arguments: args === undefined ? {} : args });
    });
  const tools = (proxy) =>
    new Proxy({}, { get: (_, tool) => (typeof tool === "string" ? (args) => call(proxy, tool, args) : undefined) });
  const connectors = new Proxy({}, { get: (_, proxy) => (typeof proxy === "string" ? tools(proxy) : undefined) });

  const settle = (id, ok, value) => {
    const entry = pending.get(id);
    if (!entry) return;
    pending.delete(id);
    if (ok) {
      entry.resolve(value);
    } else {
      const error = new Error(value.message);
      error.code = value.code;
      entry.reject(error);
    }
  };
  const describe = (e) => {
    if (e instanceof Error) return e.stack ? String(e) + "\n" + e.stack : String(e);
    return text(e);
  };
  const start = (program, input) => {
    Promise.resolve()
      .then(() => program(input))
      .then(
        (value) => {
          try {
            send({ type: "done", result: value === undefined ? null : value, console: lines });
          } catch (e) {
            send({ type: "failed", failure: { kind: "exception", message: "the result is not JSON: " + describe(e) } });
          }
        },
        (e) => send({ type: "failed", failure: { kind: "exception", message: describe(e) } }),
      );
  };

  for (const [name, value] of [["console", console], ["connectors", connectors], ["__settle", settle], ["__start", start]]) {
    Object.defineProperty(globalThis, name, { value, writable: false, configurable: false, enumerable: false });
  }
})(globalThis.print, NONCE, CONSOLE_LIMIT);
delete globalThis.print;
delete globalThis.scriptArgs;
