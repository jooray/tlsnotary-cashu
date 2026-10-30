/** WebSocket transports with the interface the WASM prover reads from. */

export interface IoChannel {
  read(): Promise<Uint8Array | null>;
  write(data: Uint8Array): Promise<void>;
  close(): Promise<void>;
}

/**
 * Subprotocols that carry a ticket to the notary (`tlsnc`, `tlsnc.<ticket>`),
 * so it never appears in a URL or an access log.
 */
export function ticketProtocols(ticket: string): string[] {
  return ["tlsnc", `tlsnc.${ticket}`];
}

/** Opens a binary WebSocket as an IoChannel. */
export function openSocket(url: string, protocols: string[] = []): Promise<IoChannel> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, protocols);
    ws.binaryType = "arraybuffer";
    const queue: Uint8Array[] = [];
    const waiters: ((v: Uint8Array | null) => void)[] = [];
    let closed = false;
    let opened = false;

    ws.onmessage = (ev) => {
      const chunk = new Uint8Array(ev.data as ArrayBuffer);
      const w = waiters.shift();
      if (w) w(chunk);
      else queue.push(chunk);
    };
    ws.onclose = () => {
      closed = true;
      while (waiters.length) waiters.shift()!(null);
      if (!opened) reject(new Error(`WebSocket to ${url} was refused`));
    };
    ws.onerror = () => {
      if (!opened) reject(new Error(`WebSocket to ${url} failed`));
    };
    ws.onopen = () => {
      opened = true;
      resolve({
        read() {
          const chunk = queue.shift();
          if (chunk) return Promise.resolve(chunk);
          if (closed) return Promise.resolve(null);
          return new Promise((r) => waiters.push(r));
        },
        async write(data) {
          if (closed || ws.readyState !== WebSocket.OPEN) throw new Error("socket closed");
          // Copy: the WASM memory view may change under us.
          ws.send(data.slice());
        },
        async close() {
          if (ws.readyState === WebSocket.OPEN) ws.close();
        },
      });
    };
  });
}

/** A channel that connects on first use (the bridge may only be opened once the notarization session runs, and the target should not sit idle during preprocessing). */
export function lazyChannel(connect: () => Promise<IoChannel>): IoChannel {
  let ch: Promise<IoChannel> | undefined;
  const get = () => (ch ??= connect());
  return {
    async read() {
      return (await get()).read();
    },
    async write(d) {
      return (await get()).write(d);
    },
    async close() {
      if (ch) return (await ch).close();
    },
  };
}
