/**
 * Browser client for tlsnotary-cashu notaries.
 *
 * ```ts
 * const client = new TlsnClient({ notary: "https://notary.example.org" });
 * const n = await client.notarize({
 *   request: { url: "https://api.example.com/me", headers: [["Authorization", "Bearer …"]] },
 *   pay: tokenPayer(token),
 * });
 * const presentation = await client.present(n, { response: { body: { json_paths: ["name"] } } });
 * ```
 *
 * The page must be cross-origin isolated (`Cross-Origin-Opener-Policy:
 * same-origin`, `Cross-Origin-Embedder-Policy: require-corp`): the prover
 * runs MPC on WebAssembly threads.
 */
import { NotaryApi, NotaryError } from "./api.js";
import type {
  Egress,
  HttpRequestSpec,
  Info,
  Notarized,
  Payer,
  Quote,
  RevealSpec,
  Step,
  TicketResponse,
} from "./types.js";
import type { WorkerRequest } from "./worker.js";


export * from "./types.js";
export { NotaryApi, NotaryError, PROTOCOL, TLSN_VERSION, decodeRequest } from "./api.js";
export { callbackPayer, cashuTsPayer, tokenPayer } from "./payers.js";

/** Bytes added to the request size estimate when picking a tier. */
const REQUEST_LEN_MARGIN = 64;

/**
 * How the prover reaches the target.
 * - `bridge`: through the notary's bridge (connections leave from the notary; priced as egress=notary).
 * - `proxy`: tlsn proxy mode, the notary connects (egress=notary).
 * - `external`: through a WebSocket-to-TCP bridge you run or trust (`bridgeUrl`); the notary's
 *   IP is not involved, so it is priced as egress=client.
 */
export type Mode = "bridge" | "proxy" | "external";

export interface ClientOptions {
  /** Notary base URL. */
  notary: string;
  /** Refuse to pay unless the notary's key is this (hex). */
  expectedKey?: string;
  /**
   * For mode `external`: bridge URL template, `{host}` and `{port}` are
   * replaced, e.g. `wss://bridge.example/?host={host}&port={port}`.
   */
  bridgeUrl?: string;
  /** Override where the worker script is loaded from. */
  workerUrl?: URL | string;
  /**
   * URL of `tlsnc_wasm.js` in the `@tlsnc/wasm` package, served as static
   * files with the package's layout intact. Default: `/tlsnc-wasm/tlsnc_wasm.js`.
   */
  wasmUrl?: URL | string;
}

export interface NotarizeOptions {
  request: HttpRequestSpec;
  mode?: Mode;
  /** Pays the notary; not called when `ticket` is given. */
  pay?: Payer;
  /** Reuse a ticket from a failed attempt instead of paying again. */
  ticket?: string;
  /** Called with the price before paying; return false to stop. */
  confirm?: (quote: Quote) => boolean | Promise<boolean>;
  /** Expected response size; default the tier's maximum. */
  maxRecv?: number;
  onStep?: (step: Step | "pay") => void;
  /** Called once the ticket is bought, so it can be shown or stored for a retry. */
  onTicket?: (ticket: TicketResponse) => void;
}

export class TlsnClient {
  readonly api: NotaryApi;
  private readonly opts: ClientOptions;
  private worker?: Worker;
  private nextId = 1;
  private pending = new Map<
    number,
    { resolve: (v: any) => void; reject: (e: Error) => void; onStep?: (s: Step) => void }
  >();
  private infoCache?: Promise<Info>;

  constructor(opts: ClientOptions) {
    this.opts = opts;
    this.api = new NotaryApi(opts.notary);
  }

  /** The notary's `/info`, checked for compatibility and the expected key. */
  info(): Promise<Info> {
    this.infoCache ??= this.api.info().then((info) => {
      NotaryApi.checkCompatible(info);
      if (this.opts.expectedKey && info.notary_key.key.toLowerCase() !== this.opts.expectedKey.toLowerCase()) {
        throw new Error(`notary key is ${info.notary_key.key}, expected ${this.opts.expectedKey}`);
      }
      return info;
    });
    return this.infoCache;
  }

  private call<T>(msg: Record<string, unknown>, onStep?: (s: Step) => void, transfer: Transferable[] = []): Promise<T> {
    if (typeof crossOriginIsolated !== "undefined" && !crossOriginIsolated) {
      return Promise.reject(
        new Error("the page is not cross-origin isolated (COOP: same-origin, COEP: require-corp); the prover needs it"),
      );
    }
    if (!this.worker) {
      // Written out literally so bundlers (Vite, webpack) find and emit the worker.
      this.worker = this.opts.workerUrl
        ? new Worker(this.opts.workerUrl, { type: "module" })
        : new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
      this.worker.onmessage = (ev) => {
        const m = ev.data as { id: number; type: string; result?: unknown; error?: string; step?: Step };
        const p = this.pending.get(m.id);
        if (!p) return;
        if (m.type === "step") p.onStep?.(m.step!);
        else {
          this.pending.delete(m.id);
          if (m.type === "done") p.resolve(m.result);
          else p.reject(new Error(m.error));
        }
      };
      this.worker.onerror = (ev) => {
        for (const p of this.pending.values()) p.reject(new Error(`prover worker: ${ev.message}`));
        this.pending.clear();
      };
    }
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve, reject, onStep });
      const wasmUrl = new URL(this.opts.wasmUrl ?? "/tlsnc-wasm/tlsnc_wasm.js", location.href).href;
      this.worker!.postMessage({ ...msg, id, wasmUrl } satisfies Partial<WorkerRequest>, transfer);
    });
  }

  /** Request size on the wire, in bytes. */
  requestBytes(request: HttpRequestSpec): Promise<number> {
    return this.call({ type: "wireLen", request: normalize(request) });
  }

  /** Picks the tier and price for a request. */
  async quote(request: HttpRequestSpec, mode: Mode = "bridge", maxRecv = 0): Promise<Quote> {
    const info = await this.info();
    const egress: Egress = mode === "external" ? "client" : "notary";
    const requestBytes = await this.requestBytes(request);
    const need = requestBytes + REQUEST_LEN_MARGIN;
    const tier = info.tiers
      .filter((t) => t.max_sent >= need && t.max_recv >= maxRecv)
      .sort((a, b) => a.max_sent - b.max_sent)[0];
    if (!tier) throw new Error(`no tier fits a ${need}-byte request`);
    return { tier, egress, price: tier.price[egress], requestBytes };
  }

  /** Pays (unless `ticket` is given) and notarizes one request. */
  async notarize(o: NotarizeOptions): Promise<Notarized> {
    const mode = o.mode ?? "bridge";
    const request = normalize(o.request);
    const target = new URL(request.url);
    if (target.protocol !== "https:") throw new Error("only https:// URLs can be notarized");
    const port = target.port ? Number(target.port) : 443;
    const info = await this.info();
    if (mode !== "external" && port !== info.egress.port) {
      throw new Error(`the notary only connects to port ${info.egress.port}`);
    }
    if (mode === "external" && !this.opts.bridgeUrl) throw new Error("mode external needs bridgeUrl");

    const quote = await this.quote(request, mode, o.maxRecv ?? 0);
    let ticket = o.ticket;
    if (!ticket) {
      if (!o.pay) throw new Error("pass pay (or a ticket)");
      if (o.confirm && !(await o.confirm(quote))) throw new Error("cancelled");
      o.onStep?.("pay");
      const bought = await this.api.buyTicket(info, quote.tier.id, quote.egress, o.pay);
      o.onTicket?.(bought);
      ticket = bought.ticket;
    }

    const ws = this.api.wsBase;
    const bridgeUrl =
      mode === "bridge"
        ? `${ws}/v1/bridge?host=${encodeURIComponent(target.hostname)}`
        : mode === "external"
          ? this.opts.bridgeUrl!.replace("{host}", encodeURIComponent(target.hostname)).replace("{port}", String(port))
          : null;
    const limits = {
      maxSent: quote.tier.max_sent,
      maxRecv: Math.min(o.maxRecv || quote.tier.max_recv, quote.tier.max_recv),
    };
    try {
      const result = await this.call<Omit<Notarized, "ticket">>(
        {
          type: "notarize",
          request,
          limits,
          notaryUrl: `${ws}/v1/notarize`,
          bridgeUrl,
          ticket,
          bridgeTicket: mode === "bridge",
        },
        o.onStep,
      );
      return { ...result, ticket };
    } catch (e) {
      throw await this.explain(e as Error, ticket);
    }
  }

  /** Browsers hide why a WebSocket upgrade failed; ask the notary. */
  private async explain(err: Error, ticket: string): Promise<Error> {
    if (!/WebSocket/.test(err.message)) return withTicket(err, ticket);
    try {
      const s = await this.api.ticketStatus(ticket);
      if (s.spent) return withTicket(new Error("the ticket was already used"), ticket);
      if (s.expired) return withTicket(new Error("the ticket expired"), ticket);
      if (s.attempts_left === 0) return withTicket(new Error("no attempts left on this ticket"), ticket);
      if (s.session_running) return withTicket(new Error("a session for this ticket is already running"), ticket);
      if (!s.capacity_available) return withTicket(new Error("the notary is busy; retry shortly with the same ticket"), ticket);
    } catch (e) {
      if (e instanceof NotaryError) return withTicket(e, ticket);
    }
    return withTicket(err, ticket);
  }

  /** Builds a presentation that reveals only what `spec` lists. */
  present(n: Pick<Notarized, "attestation" | "secrets">, spec: RevealSpec = {}): Promise<Uint8Array> {
    return this.call({ type: "present", attestation: n.attestation, secrets: n.secrets, spec: fillSpec(spec) });
  }

  /** Stops the prover worker. */
  close(): void {
    this.worker?.terminate();
    this.worker = undefined;
  }
}

function withTicket(err: Error, ticket: string): Error {
  const e = new Error(`${err.message} (ticket ${ticket} can be reused for a retry)`);
  (e as Error & { ticket?: string }).ticket = ticket;
  return e;
}

function normalize(r: HttpRequestSpec): Required<Omit<HttpRequestSpec, "body">> & { body?: string } {
  return { url: r.url, method: (r.method ?? "GET").toUpperCase(), headers: r.headers ?? [], body: r.body };
}

/** serde needs every field; fill the defaults the Rust side uses. */
function fillSpec(spec: RevealSpec) {
  const body = spec.response?.body ?? "all";
  return {
    request: {
      target: spec.request?.target ?? true,
      headers: spec.request?.headers ?? ["host"],
      body: spec.request?.body ?? false,
    },
    response: {
      headers: spec.response?.headers ?? ["date", "content-type"],
      body,
    },
    allow_credentials: spec.allow_credentials ?? false,
  };
}
