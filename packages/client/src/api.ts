/** The notary's HTTP API: `/info`, tickets (NUT-24), ticket status. */
import { decodePaymentRequest } from "@cashu/cashu-ts";
import type { Egress, Info, Payer, PaymentRequestInfo, TicketResponse, TicketStatus } from "./types.js";

/** This build's protocol versions; a notary advertising others is refused. */
export const PROTOCOL = "tlsnc/1";
export const TLSN_VERSION = "0.1.0-alpha.16-pre+24b10ba";

export class NotaryError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly code?: string,
    readonly body?: unknown,
  ) {
    super(message);
  }
}

async function fail(resp: Response, what: string): Promise<never> {
  let body: { code?: string; error?: string } | undefined;
  try {
    body = await resp.json();
  } catch {
    // not JSON
  }
  throw new NotaryError(`${what}: ${body?.error ?? `HTTP ${resp.status}`}`, resp.status, body?.code, body);
}

export function decodeRequest(encoded: string): PaymentRequestInfo {
  const pr = decodePaymentRequest(encoded);
  if (pr.amount === undefined) throw new Error("payment request without an amount");
  return {
    encoded,
    amount: Number(pr.amount.toString()),
    unit: pr.unit ?? "",
    mints: pr.mints ?? [],
    description: pr.description,
  };
}

export class NotaryApi {
  readonly base: string;

  constructor(base: string) {
    this.base = base.replace(/\/+$/, "");
  }

  /** `wss://…` for `https://…`. */
  get wsBase(): string {
    return this.base.replace(/^http/, "ws");
  }

  async info(): Promise<Info> {
    const resp = await fetch(`${this.base}/info`);
    if (!resp.ok) await fail(resp, "info");
    return resp.json();
  }

  static checkCompatible(info: Info): void {
    if (info.protocol !== PROTOCOL) throw new Error(`notary speaks ${info.protocol}, this client ${PROTOCOL}`);
    if (info.tlsn_version !== TLSN_VERSION) {
      throw new Error(`notary runs tlsn ${info.tlsn_version}, this client ${TLSN_VERSION}`);
    }
  }

  /** Asks for the price of a ticket: the NUT-18 request from the 402. */
  async paymentRequest(tier: string, egress: Egress): Promise<PaymentRequestInfo> {
    const resp = await fetch(this.ticketUrl(tier, egress), { method: "POST" });
    if (resp.status !== 402) await fail(resp, "ticket");
    const creq = resp.headers.get("x-cashu");
    if (!creq) throw new Error("402 without an X-Cashu payment request (is X-Cashu exposed by CORS?)");
    return decodeRequest(creq);
  }

  /** Buys a ticket, checking the request against what `/info` advertises before paying. */
  async buyTicket(info: Info, tier: string, egress: Egress, pay: Payer): Promise<TicketResponse> {
    const t = info.tiers.find((x) => x.id === tier);
    if (!t) throw new Error(`no tier ${tier}`);
    const expected = t.price[egress];
    const request = await this.paymentRequest(tier, egress);
    if (request.amount !== expected) {
      throw new Error(`notary asks ${request.amount} sat but advertises ${expected}; refusing to pay`);
    }
    if (request.unit !== "sat") throw new Error(`unexpected unit ${request.unit}`);
    const token = await pay(request);
    const resp = await fetch(this.ticketUrl(tier, egress), {
      method: "POST",
      headers: { "X-Cashu": token.trim() },
    });
    if (!resp.ok) await fail(resp, "ticket");
    return resp.json();
  }

  async ticketStatus(ticket: string): Promise<TicketStatus> {
    const resp = await fetch(`${this.base}/v1/tickets/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ticket }),
    });
    if (!resp.ok) await fail(resp, "ticket status");
    return resp.json();
  }

  private ticketUrl(tier: string, egress: Egress): string {
    return `${this.base}/v1/tickets?tier=${encodeURIComponent(tier)}&egress=${egress}`;
  }
}
