/**
 * Verification of tlsnotary-cashu presentations.
 *
 * Checks the notary's signature against keys you trust, the server's
 * certificate chain (Mozilla roots) and handshake signature, and that the
 * revealed bytes match the attested commitments. No network access.
 */
import init, { verifyPresentation } from "../wasm/tlsnc_verify.js";

/** A notary key, as published in a notary's `/info` and `/.well-known/tlsnc-notary.json`. */
export interface NotaryKey {
  /** `k256` (secp256k1); `secp256k1` is accepted as an alias. */
  alg: string;
  /** SEC1 public key, hex. */
  key: string;
  /** Unix seconds; connections before this are not covered by the key. */
  valid_from?: number;
  /** Unix seconds; connections after this are rejected (rotated or leaked key). */
  valid_until?: number;
}

export interface Verified {
  notary_key: NotaryKey;
  /** The server the prover talked to; its certificate was checked. */
  server_name: string;
  /** Unix seconds of the TLS connection, as recorded by the notary. */
  time: number;
  /** Sent bytes, undisclosed ones replaced by `mask`. */
  sent: string;
  /** Received bytes, undisclosed ones replaced by `mask`. */
  received: string;
  sent_disclosed: [number, number][];
  received_disclosed: [number, number][];
  mask: string;
}

let ready: Promise<unknown> | undefined;

/**
 * Loads the WebAssembly module. Called by `verify` on first use; call it
 * yourself to load early or to pass the module bytes (e.g. in Node:
 * `await initVerify(readFileSync(new URL("../wasm/tlsnc_verify_bg.wasm", import.meta.url)))`).
 */
export function initVerify(module?: BufferSource | URL | Response): Promise<unknown> {
  ready ??= init(module === undefined ? undefined : { module_or_path: module });
  return ready;
}

/**
 * Verifies a presentation. Throws if the signature is not from one of
 * `trustedKeys`, if the key was outside its validity window at connection
 * time, or if anything in the presentation does not check out.
 */
export async function verify(presentation: Uint8Array, trustedKeys: NotaryKey[]): Promise<Verified> {
  await initVerify();
  return JSON.parse(verifyPresentation(presentation, JSON.stringify(trustedKeys))) as Verified;
}

/** Fetches the keys a notary publishes. Trust them only if you trust that origin. */
export async function fetchNotaryKeys(notaryUrl: string): Promise<NotaryKey[]> {
  const resp = await fetch(new URL("/.well-known/tlsnc-notary.json", notaryUrl));
  if (!resp.ok) throw new Error(`well-known: HTTP ${resp.status}`);
  const body = (await resp.json()) as { keys: NotaryKey[] };
  return body.keys;
}

/** The parts of a verified transcript the prover chose to reveal, as text runs. */
export function disclosedRuns(text: string, ranges: [number, number][]): string[] {
  const bytes = new TextEncoder().encode(text);
  return ranges.map(([a, b]) => new TextDecoder().decode(bytes.slice(a, b)));
}
