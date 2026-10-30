import { cpSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig, type Plugin } from "vite";

const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));
// Every build gets its own id, so a redeploy is always detected as new.
const VERSION = `${pkg.version}+${new Date().toISOString().replace(/[-:T.Z]/g, "").slice(0, 14)}`;

// The prover runs on WebAssembly threads: the page must be cross-origin
// isolated. Production nginx sends the same headers (deploy/nginx-tlsnc.conf).
const isolation = {
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
};

// The notary to proxy to in development.
const NOTARY = process.env.TLSNC_NOTARY ?? "http://127.0.0.1:7150";

// The prover package is served as static files with its layout intact (its
// thread spawner resolves its own files relative to itself; see
// packages/client/src/worker.ts). Copied into public/ for dev and build.
const WASM_PKG = new URL("../../wasm/prover/pkg/", import.meta.url).pathname;
const WASM_PUBLIC = new URL("./public/tlsnc-wasm/", import.meta.url).pathname;
if (!existsSync(WASM_PKG)) throw new Error("build the prover first: wasm/prover/build.sh");
rmSync(WASM_PUBLIC, { recursive: true, force: true });
cpSync(WASM_PKG, WASM_PUBLIC, { recursive: true });

/** Writes version.json and stamps the service worker with the version. */
function versionPlugin(): Plugin {
  return {
    name: "tlsnc-version",
    apply: "build",
    writeBundle(opts) {
      const out = opts.dir ?? "dist";
      writeFileSync(resolve(out, "version.json"), JSON.stringify({ version: VERSION }) + "\n");
      const sw = readFileSync(resolve(out, "sw.js"), "utf8").replace("__APP_VERSION__", VERSION);
      writeFileSync(resolve(out, "sw.js"), sw);
    },
  };
}

export default defineConfig({
  // The site root is the static info page (apps/site); the app lives under /app/.
  base: "/app/",
  define: { __APP_VERSION__: JSON.stringify(VERSION) },
  server: {
    headers: isolation,
    proxy: {
      "/info": NOTARY,
      "/.well-known": NOTARY,
      "/v1": { target: NOTARY, ws: true },
    },
  },
  preview: {
    headers: isolation,
    proxy: {
      "/info": NOTARY,
      "/.well-known": NOTARY,
      "/v1": { target: NOTARY, ws: true },
    },
  },
  optimizeDeps: { exclude: ["@tlsnc/wasm", "@tlsnc/client", "@tlsnc/verify"] },
  worker: { format: "es" },
  build: { target: "es2022" },
  plugins: [versionPlugin()],
});
