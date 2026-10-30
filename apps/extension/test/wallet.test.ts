// Network test against the public test mint (it pays its own invoices).
// Run: node --test test/   (set TLSNC_OFFLINE=1 to skip)
import { test } from "node:test";
import assert from "node:assert/strict";
import { CashuWallet, type Store } from "../src/wallet.ts";

const MINT = "https://testnut.cashu.space";

function memoryStore(): Store & { data: Map<string, unknown> } {
  const data = new Map<string, unknown>();
  return {
    data,
    async get(k) {
      const v = data.get(k);
      return v === undefined ? undefined : structuredClone(v) as never;
    },
    async set(k, v) {
      data.set(k, structuredClone(v));
    },
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("mint, send, receive, pay, restore", { skip: !!process.env.TLSNC_OFFLINE, timeout: 120_000 }, async () => {
  const a = new CashuWallet(memoryStore());
  const words = await a.mnemonic();
  assert.equal(words.split(" ").length, 12);

  const q = await a.requestInvoice(MINT, 64);
  assert.match(q.request, /^lnbc/i);
  let minted: { amount: number }[] = [];
  for (let i = 0; i < 20 && !minted.length; i++) {
    minted = await a.checkQuotes();
    if (!minted.length) await sleep(1000);
  }
  assert.equal(minted[0]?.amount, 64);
  assert.deepEqual(await a.balances(), { [MINT]: 64 });

  const { token, entry } = await a.send(MINT, 10);
  assert.ok(await a.tokenUnspent(entry.id));
  const b = new CashuWallet(memoryStore());
  const got = await b.receive(token);
  assert.ok(got.amount >= 9, `received ${got.amount}`);
  assert.equal(await a.tokenUnspent(entry.id), false);

  const paid = await a.pay({ amount: 5, mints: [MINT + "/"] }, "test");
  assert.equal(paid.entry.kind, "pay");
  const back = await a.reclaim(paid.entry.id);
  assert.ok(back >= 4);

  const before = (await a.balances())[MINT];
  const c = new CashuWallet(memoryStore());
  const found = await c.restore(words, [MINT]);
  assert.equal(found[MINT], before);
  // counters advanced: a new receive must not reuse outputs
  const again = await c.send(MINT, 3);
  assert.ok(again.token.startsWith("cashuB"));
  assert.equal(await c.sync(), 0);

  const h = await a.history();
  assert.deepEqual(new Set(h.map((e) => e.kind)), new Set(["mint", "send", "pay", "reclaim"]));
});
