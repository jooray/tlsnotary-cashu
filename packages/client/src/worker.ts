/**
 * Runs the WASM prover off the main thread. Started by `TlsnClient`; the
 * page must be cross-origin isolated (COOP/COEP) for the prover's threads.
 *
 * The `@tlsnc/wasm` package is loaded at run time from `wasmUrl`, not
 * bundled: its thread spawner finds its own files (`snippets/…/spawn.js`,
 * the `.wasm`) by paths relative to the package, which bundlers rewrite.
 * Serve the package directory as static files.
 */
import type * as Wasm from "@tlsnc/wasm";
import { lazyChannel, openSocket, ticketProtocols } from "./io.js";

let wasm: typeof Wasm;

export type WorkerRequest = { wasmUrl: string } & (
  | { id: number; type: "wireLen"; request: unknown }
  | {
      id: number;
      type: "notarize";
      request: unknown;
      limits: { maxSent: number; maxRecv: number };
      notaryUrl: string;
      /** Bridge URL (ours or a third party's); null for proxy mode. */
      bridgeUrl: string | null;
      ticket: string;
      /** Whether the bridge needs the ticket (ours does, a third party's does not). */
      bridgeTicket: boolean;
    }
  | { id: number; type: "present"; attestation: Uint8Array; secrets: Uint8Array; spec: unknown }
);

let ready: Promise<void> | undefined;

function start(wasmUrl: string): Promise<void> {
  ready ??= (async () => {
    wasm = await import(/* @vite-ignore */ /* webpackIgnore: true */ wasmUrl);
    await wasm.default();
    const threads = Math.max(2, Math.min(navigator.hardwareConcurrency || 4, 8));
    await wasm.initialize(threads);
  })();
  return ready;
}

const post = (msg: unknown, transfer: Transferable[] = []) =>
  (self as unknown as Worker).postMessage(msg, transfer);

self.onmessage = async (ev: MessageEvent<WorkerRequest>) => {
  const msg = ev.data;
  try {
    await start(msg.wasmUrl);
    if (msg.type === "wireLen") {
      post({ id: msg.id, type: "done", result: wasm.requestWireLen(msg.request) });
    } else if (msg.type === "present") {
      const bytes = wasm.present(msg.attestation, msg.secrets, msg.spec);
      post({ id: msg.id, type: "done", result: bytes }, [bytes.buffer]);
    } else if (msg.type === "notarize") {
      const notary = await openSocket(msg.notaryUrl, ticketProtocols(msg.ticket));
      const bridgeUrl = msg.bridgeUrl;
      // A third party's bridge gets no ticket and no subprotocol.
      const protocols = msg.bridgeTicket ? ticketProtocols(msg.ticket) : [];
      const server = bridgeUrl ? lazyChannel(() => openSocket(bridgeUrl, protocols)) : null;
      const result = await wasm.notarize(msg.request, msg.limits, notary, server, (step: string) =>
        post({ id: msg.id, type: "step", step }),
      );
      post({ id: msg.id, type: "done", result }, [
        result.attestation.buffer,
        result.secrets.buffer,
        result.response.body.buffer,
      ]);
    }
  } catch (e) {
    post({ id: msg.id, type: "error", error: e instanceof Error ? e.message : String(e) });
  }
};
