/** Wire types of a tlsnotary-cashu notary (mirrors crates/protocol). */

export type Egress = "client" | "notary";

export interface Prices {
  client: number;
  notary: number;
}

export interface TierInfo {
  id: string;
  max_sent: number;
  max_recv: number;
  max_recv_online: number;
  timeout_secs: number;
  price: Prices;
}

export interface NotaryKey {
  alg: string;
  key: string;
  valid_from?: number;
  valid_until?: number;
}

export interface Info {
  protocol: string;
  tlsn_version: string;
  name: string;
  description: string;
  unit: string;
  mints: string[];
  tiers: TierInfo[];
  notary_key: NotaryKey;
  previous_keys: NotaryKey[];
  ticket_ttl_secs: number;
  ticket_attempts: number;
  egress: { port: number; per_host_per_hour: number };
}

export interface TicketResponse {
  ticket: string;
  expires_at: number;
  attempts: number;
  tier: TierInfo;
  egress: Egress;
  received: number;
}

export interface TicketStatus {
  tier: string;
  egress: Egress;
  expires_at: number;
  attempts_left: number;
  spent: boolean;
  expired: boolean;
  session_running: boolean;
  capacity_available: boolean;
}

/** The HTTPS request to notarize. Headers are `[name, value]` pairs. */
export interface HttpRequestSpec {
  url: string;
  method?: string;
  headers?: [string, string][];
  body?: string;
}

export interface HttpResponse {
  status: number;
  headers: [string, string][];
  body: Uint8Array;
}

/** What a presentation discloses. Unlisted header values stay hidden. */
export interface RevealSpec {
  request?: {
    /** The path and query (default true). */
    target?: boolean;
    /** Header names whose values are revealed (default ["host"]). */
    headers?: string[];
    body?: boolean;
  };
  response?: {
    /** Header names whose values are revealed (default ["date", "content-type"]). */
    headers?: string[];
    /** "all" (default), "none", or `{ json_paths: ["data.balance"] }`. */
    body?: "all" | "none" | { json_paths: string[] };
  };
  /** Allow revealing Authorization, Cookie and similar values. */
  allow_credentials?: boolean;
}

/** A NUT-18 payment request as the notary sent it (decoded). */
export interface PaymentRequestInfo {
  /** The encoded request (`creqA…`). */
  encoded: string;
  amount: number;
  unit: string;
  mints: string[];
  description?: string;
}

/** Pays a payment request and returns a Cashu token (`cashuB…`). */
export type Payer = (request: PaymentRequestInfo) => Promise<string>;

export type Step = "setup" | "request" | "prove" | "attest";

export interface Notarized {
  attestation: Uint8Array;
  secrets: Uint8Array;
  response: HttpResponse;
  ticket: string;
}

export interface Quote {
  tier: TierInfo;
  egress: Egress;
  price: number;
  requestBytes: number;
}
