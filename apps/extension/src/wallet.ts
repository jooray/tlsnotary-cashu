/**
 * A small Cashu wallet (cashu-ts) for paying notaries.
 *
 * Secrets are deterministic (NUT-13) from a BIP-39 mnemonic, so the 12
 * words are the backup: `restore` asks each mint (NUT-09) for the
 * signatures it issued and keeps the unspent ones. Proofs, counters and the
 * history live in a `Store` (chrome.storage.local in the extension, memory
 * in tests). Every operation that touches proofs runs under one lock, shared
 * by the popup, the notarize page and the background worker.
 */
import {
  Amount,
  type CounterSource,
  type MintQuoteBolt11Response,
  type Proof,
  type ProofLike,
  Wallet,
  getEncodedToken,
  getTokenMetadata,
  mnemonicToSeedSync,
} from "@cashu/cashu-ts";
import { generateMnemonic, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

export interface Store {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
}

/** A proof as stored: the amount as a plain number. */
export type StoredProof = Omit<Proof, "amount"> & { amount: number };

export type HistoryKind = "receive" | "mint" | "send" | "pay" | "refund" | "restore" | "reclaim";

export interface HistoryEntry {
  id: string;
  time: number;
  kind: HistoryKind;
  mint: string;
  /** Positive for money in, negative for money out. */
  amount: number;
  /** Mint fees paid on top. */
  fee?: number;
  note?: string;
  /** A sent token, kept so it can be taken back while it is unspent. */
  token?: string;
  /** Notary ticket bought with a payment, for a retry. */
  ticket?: string;
}

export interface PendingQuote {
  mint: string;
  quote: string;
  amount: number;
  request: string;
  expiry: number | null;
  created: number;
}

const K = {
  mnemonic: "wallet.mnemonic",
  proofs: "wallet.proofs",
  counters: "wallet.counters",
  history: "wallet.history",
  quotes: "wallet.quotes",
} as const;

const sum = (ps: { amount: unknown }[]) => ps.reduce((s: number, p) => s + Number(String(p.amount)), 0);
const toStored = (ps: ProofLike[]): StoredProof[] =>
  ps.map((p) => ({ ...(p as Proof), amount: Number(p.amount.toString()) }));
export const normalizeMint = (url: string) => url.trim().replace(/\/+$/, "");

/** The mint a token is from; throws if it is not a Cashu token. */
export function tokenMint(token: string): string {
  try {
    return normalizeMint(getTokenMetadata(token.trim()).mint);
  } catch {
    throw new Error("not a Cashu token (cashuA… or cashuB…)");
  }
}

/** Serializes work across tabs and workers (Web Locks), or within one context without them. */
let chain: Promise<unknown> = Promise.resolve();
function withLock<T>(fn: () => Promise<T>): Promise<T> {
  const locks = (globalThis.navigator as Navigator | undefined)?.locks;
  if (locks) return locks.request("tlsnc-wallet", fn) as Promise<T>;
  const run = chain.then(fn, fn);
  chain = run.catch(() => undefined);
  return run;
}

export class CashuWallet {
  private wallets = new Map<string, Promise<Wallet>>();
  private seed?: Uint8Array;
  private readonly store: Store;

  constructor(store: Store) {
    this.store = store;
  }

  /** The mnemonic, created on first use. */
  async mnemonic(): Promise<string> {
    let m = await this.store.get<string>(K.mnemonic);
    if (!m) {
      m = generateMnemonic(wordlist, 128);
      await this.store.set(K.mnemonic, m);
    }
    return m;
  }

  private async seedBytes(): Promise<Uint8Array> {
    this.seed ??= mnemonicToSeedSync(await this.mnemonic());
    return this.seed;
  }

  /** Counters persisted in the store; only called inside `withLock`. */
  private counterSource(): CounterSource {
    const load = async () => (await this.store.get<Record<string, number>>(K.counters)) ?? {};
    return {
      reserve: async (keysetId, n) => {
        const c = await load();
        const start = c[keysetId] ?? 0;
        if (n > 0) {
          c[keysetId] = start + n;
          await this.store.set(K.counters, c);
        }
        return { start, count: n };
      },
      advanceToAtLeast: async (keysetId, minNext) => {
        const c = await load();
        if ((c[keysetId] ?? 0) < minNext) {
          c[keysetId] = minNext;
          await this.store.set(K.counters, c);
        }
      },
      snapshot: load,
    };
  }

  private wallet(mint: string): Promise<Wallet> {
    mint = normalizeMint(mint);
    let w = this.wallets.get(mint);
    if (!w) {
      w = (async () => {
        const wallet = new Wallet(mint, {
          unit: "sat",
          bip39seed: await this.seedBytes(),
          counterSource: this.counterSource(),
        });
        await wallet.loadMint();
        return wallet;
      })();
      w.catch(() => this.wallets.delete(mint));
      this.wallets.set(mint, w);
    }
    return w;
  }

  private async allProofs(): Promise<Record<string, StoredProof[]>> {
    return (await this.store.get<Record<string, StoredProof[]>>(K.proofs)) ?? {};
  }

  private async setProofs(mint: string, proofs: StoredProof[]): Promise<void> {
    const all = await this.allProofs();
    if (proofs.length) all[mint] = proofs;
    else delete all[mint];
    await this.store.set(K.proofs, all);
  }

  private async addProofs(mint: string, proofs: ProofLike[]): Promise<void> {
    const have = (await this.allProofs())[mint] ?? [];
    const secrets = new Set(have.map((p) => p.secret));
    await this.setProofs(mint, [...have, ...toStored(proofs).filter((p) => !secrets.has(p.secret))]);
  }

  private async log(e: Omit<HistoryEntry, "id" | "time">): Promise<HistoryEntry> {
    const entry: HistoryEntry = { id: crypto.randomUUID(), time: Math.floor(Date.now() / 1000), ...e };
    const h = (await this.store.get<HistoryEntry[]>(K.history)) ?? [];
    h.unshift(entry);
    await this.store.set(K.history, h.slice(0, 500));
    return entry;
  }

  async history(): Promise<HistoryEntry[]> {
    return (await this.store.get<HistoryEntry[]>(K.history)) ?? [];
  }

  async updateHistory(id: string, patch: Partial<HistoryEntry>): Promise<void> {
    const h = await this.history();
    const e = h.find((x) => x.id === id);
    if (e) Object.assign(e, patch);
    await this.store.set(K.history, h);
  }

  /** Balance per mint, in sat. */
  async balances(): Promise<Record<string, number>> {
    const out: Record<string, number> = {};
    for (const [mint, ps] of Object.entries(await this.allProofs())) out[mint] = sum(ps);
    return out;
  }

  /** Swaps a token into the wallet. Returns what was received after mint fees. */
  receive(token: string, kind: HistoryKind = "receive", note?: string) {
    return withLock(async () => {
      token = token.trim();
      const mint = tokenMint(token);
      const wallet = await this.wallet(mint);
      const gross = sum(wallet.decodeToken(token).proofs);
      const proofs = await wallet.receive(token);
      await this.addProofs(mint, proofs);
      const amount = sum(proofs);
      await this.log({ kind, mint, amount, fee: gross - amount || undefined, note });
      return { mint, amount };
    });
  }

  /** Asks the mint for a Lightning invoice; `checkQuotes` mints once it is paid. */
  async requestInvoice(mint: string, amount: number): Promise<PendingQuote> {
    mint = normalizeMint(mint);
    const wallet = await this.wallet(mint);
    const q = await wallet.createMintQuoteBolt11(amount);
    const pending: PendingQuote = {
      mint,
      quote: q.quote,
      amount,
      request: q.request,
      expiry: q.expiry,
      created: Math.floor(Date.now() / 1000),
    };
    await withLock(async () => {
      const qs = (await this.store.get<PendingQuote[]>(K.quotes)) ?? [];
      await this.store.set(K.quotes, [...qs, pending]);
    });
    return pending;
  }

  async pendingQuotes(): Promise<PendingQuote[]> {
    return (await this.store.get<PendingQuote[]>(K.quotes)) ?? [];
  }

  /** Mints every paid invoice; drops expired ones. Returns what was minted. */
  checkQuotes(): Promise<{ mint: string; amount: number }[]> {
    return withLock(async () => {
      const qs = await this.pendingQuotes();
      if (!qs.length) return [];
      const keep: PendingQuote[] = [];
      const minted: { mint: string; amount: number }[] = [];
      const now = Math.floor(Date.now() / 1000);
      for (const q of qs) {
        try {
          const wallet = await this.wallet(q.mint);
          const s: MintQuoteBolt11Response = await wallet.checkMintQuoteBolt11(q.quote);
          if (s.state === "PAID") {
            const proofs = await wallet.mintProofsBolt11(q.amount, s);
            await this.addProofs(q.mint, proofs);
            await this.log({ kind: "mint", mint: q.mint, amount: sum(proofs), note: "Lightning" });
            minted.push({ mint: q.mint, amount: sum(proofs) });
          } else if (s.state === "ISSUED" || (q.expiry && q.expiry < now)) {
            // done elsewhere or expired unpaid
          } else keep.push(q);
        } catch {
          // mint unreachable; try again later unless long expired
          if (!q.expiry || q.expiry > now - 86400) keep.push(q);
        }
      }
      await this.store.set(K.quotes, keep);
      return minted;
    });
  }

  async cancelQuote(quote: string): Promise<void> {
    await withLock(async () => {
      const qs = await this.pendingQuotes();
      await this.store.set(K.quotes, qs.filter((q) => q.quote !== quote));
    });
  }

  /**
   * Takes `amount` sat out as a token (plus the receiver's input fees if
   * `includeFees`). The token is kept in the history so it can be reclaimed.
   */
  send(mint: string, amount: number, opts: { kind?: HistoryKind; note?: string; includeFees?: boolean } = {}) {
    return withLock(async () => {
      mint = normalizeMint(mint);
      const have = (await this.allProofs())[mint] ?? [];
      if (sum(have) < amount) throw new Error(`only ${sum(have)} sat at ${mint}`);
      const wallet = await this.wallet(mint);
      const { keep, send } = await wallet.send(amount, have, { includeFees: opts.includeFees ?? false });
      await this.setProofs(mint, toStored(keep));
      const token = getEncodedToken({ mint, proofs: send, unit: "sat" });
      const spent = sum(have) - sum(keep);
      const entry = await this.log({
        kind: opts.kind ?? "send",
        mint,
        amount: -spent,
        fee: spent - amount || undefined,
        note: opts.note,
        token,
      });
      return { token, entry };
    });
  }

  /**
   * Pays a NUT-18 request from the first of its mints with enough balance.
   * The amount is net of the notary's input fees, so those are added.
   */
  async pay(request: { amount: number; mints: string[] }, note?: string) {
    const balances = await this.balances();
    for (const m of request.mints) {
      const mint = normalizeMint(m);
      if ((balances[mint] ?? 0) >= request.amount) {
        try {
          return await this.send(mint, request.amount, { kind: "pay", note, includeFees: true });
        } catch (e) {
          // fees may push it over the balance; try the next mint
          if (!/only \d+ sat|Not enough/i.test(String(e))) throw e;
        }
      }
    }
    throw new Error(
      `not enough sat at any accepted mint (${request.amount} sat needed + fees; accepted: ${request.mints.join(", ")})`,
    );
  }

  /** Takes back a token sent earlier, if nobody redeemed it. */
  async reclaim(entryId: string): Promise<number> {
    const e = (await this.history()).find((x) => x.id === entryId);
    if (!e?.token) throw new Error("nothing to reclaim");
    const { amount } = await this.receive(e.token, "reclaim", e.note);
    await this.updateHistory(entryId, { token: undefined });
    return amount;
  }

  /** Whether the token of a history entry is still unspent. */
  async tokenUnspent(entryId: string): Promise<boolean> {
    const e = (await this.history()).find((x) => x.id === entryId);
    if (!e?.token) return false;
    const wallet = await this.wallet(e.mint);
    const proofs = wallet.decodeToken(e.token).proofs;
    const states = await wallet.checkProofsStates(proofs);
    return states.every((s) => s.state === "UNSPENT");
  }

  /** Drops proofs the mint reports as spent (e.g. after a restore on another device). */
  sync(): Promise<number> {
    return withLock(async () => {
      let removed = 0;
      for (const [mint, ps] of Object.entries(await this.allProofs())) {
        const wallet = await this.wallet(mint);
        const states = await wallet.checkProofsStates(ps);
        const live = ps.filter((_, i) => states[i]?.state !== "SPENT");
        removed += sum(ps) - sum(live);
        await this.setProofs(mint, live);
      }
      return removed;
    });
  }

  /** All proofs of a mint as one token; they leave the wallet. */
  exportMint(mint: string) {
    return withLock(async () => {
      mint = normalizeMint(mint);
      const ps = (await this.allProofs())[mint] ?? [];
      if (!ps.length) throw new Error(`no proofs at ${mint}`);
      const proofs: Proof[] = ps.map((p) => ({ ...p, amount: Amount.from(p.amount) }));
      const token = getEncodedToken({ mint, proofs, unit: "sat" });
      await this.setProofs(mint, []);
      await this.log({ kind: "send", mint, amount: -sum(ps), note: "export", token });
      return token;
    });
  }

  static validMnemonic(words: string): boolean {
    return validateMnemonic(words.trim().toLowerCase().split(/\s+/).join(" "), wordlist);
  }

  /**
   * Replaces the mnemonic and recovers its unspent proofs from `mints`.
   * Proofs of the previous mnemonic stay in the wallet.
   */
  restore(words: string, mints: string[], onProgress?: (mint: string) => void) {
    return withLock(async () => {
      const m = words.trim().toLowerCase().split(/\s+/).join(" ");
      if (!validateMnemonic(m, wordlist)) throw new Error("not a valid 12/24-word BIP-39 mnemonic");
      await this.store.set(K.mnemonic, m);
      this.seed = undefined;
      this.wallets.clear();
      const found: Record<string, number> = {};
      for (const raw of mints) {
        const mint = normalizeMint(raw);
        onProgress?.(mint);
        try {
          const wallet = await this.wallet(mint);
          let got: Proof[] = [];
          for (const ks of wallet.keyChain.getKeysets()) {
            if (ks.unit !== "sat") continue;
            const { proofs, lastCounterWithSignature } = await wallet.batchRestore(100, undefined, 0, ks.id);
            if (lastCounterWithSignature !== undefined) {
              await this.counterSource().advanceToAtLeast(ks.id, lastCounterWithSignature + 1);
            }
            got = got.concat(proofs);
          }
          if (!got.length) continue;
          const states = await wallet.checkProofsStates(got);
          const unspent = got.filter((_, i) => states[i]?.state === "UNSPENT");
          if (!unspent.length) continue;
          await this.addProofs(mint, unspent);
          found[mint] = sum(unspent);
          await this.log({ kind: "restore", mint, amount: sum(unspent), note: "from mnemonic" });
        } catch (e) {
          found[mint] = -1;
          console.warn(`restore at ${mint}:`, e);
        }
      }
      return found;
    });
  }
}
