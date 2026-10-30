/** Ways to pay a notary. The library never holds a wallet itself. */
import { getEncodedToken } from "@cashu/cashu-ts";
import type { Payer, PaymentRequestInfo } from "./types.js";

/** Pays with a token you already have (it must be from one of the notary's mints). */
export function tokenPayer(token: string): Payer {
  return async () => token;
}

/** Hands the request to your UI (show it, let the user pay, return the token). */
export function callbackPayer(ask: (request: PaymentRequestInfo) => Promise<string>): Payer {
  return ask;
}

/** The parts of a `@cashu/cashu-ts` Wallet this adapter uses. */
interface CashuTsWallet {
  ops: {
    send(
      amount: number,
      proofs: unknown[],
    ): { includeFees(v: boolean): { run(): Promise<{ keep: unknown[]; send: unknown[] }> } };
  };
}

/**
 * Pays from `@cashu/cashu-ts` wallets: the first one whose mint the notary
 * accepts and whose proofs cover the amount (plus the notary's input fees).
 * `saveProofs` is called with the proofs to keep before the token is sent,
 * so a crash cannot lose them.
 */
export function cashuTsPayer(opts: {
  /** Loaded wallets, by mint URL. */
  wallets: Record<string, CashuTsWallet>;
  getProofs: (mintUrl: string) => Promise<unknown[]>;
  saveProofs: (mintUrl: string, keep: unknown[], sent: unknown[]) => Promise<void>;
}): Payer {
  return async (request) => {
    for (const mint of request.mints) {
      const wallet = opts.wallets[mint];
      if (!wallet) continue;
      const proofs = await opts.getProofs(mint);
      const total = proofs.reduce((s: number, p) => s + Number((p as { amount: unknown }).amount), 0);
      if (total < request.amount) continue;
      const { keep, send } = await wallet.ops.send(request.amount, proofs).includeFees(true).run();
      await opts.saveProofs(mint, keep, send);
      return getEncodedToken({ mint, proofs: send as never, unit: "sat" });
    }
    throw new Error(`no wallet with ${request.amount} sat at any of: ${request.mints.join(", ")}`);
  };
}
