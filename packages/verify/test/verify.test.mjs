// Verifies a presentation made by the CLI. Generate one with:
//   tlsnc notarize … --out x && tlsnc present x -o test/fixture.presentation
// and put the notary key in test/fixture.key.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { initVerify, verify } from "../dist/index.js";

const dir = new URL("./", import.meta.url);
const have = existsSync(new URL("fixture.presentation", dir));

test("verifies a CLI presentation", { skip: !have && "no fixture" }, async () => {
  await initVerify(readFileSync(new URL("../wasm/tlsnc_verify_bg.wasm", import.meta.url)));
  const presentation = readFileSync(new URL("fixture.presentation", dir));
  const key = readFileSync(new URL("fixture.key", dir), "utf8").trim();
  const v = await verify(presentation, [{ alg: "k256", key }]);
  assert.equal(v.server_name, "httpbin.org");
  assert.match(v.sent, /^GET \/json HTTP\/1\.1/);
  assert.match(v.received, /"author": "Yours Truly"/);
  await assert.rejects(verify(presentation, [{ alg: "k256", key: "02" + "11".repeat(32) }]), /untrusted/);
  await assert.rejects(verify(presentation, [{ alg: "k256", key, valid_until: 1 }]), /not valid/);
});
