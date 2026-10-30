import { cpSync, existsSync, rmSync } from "node:fs";
import { defineConfig } from "vite";

// The prover package is shipped as static files with its layout intact (its
// thread spawner finds its own files relative to itself; see
// packages/client/src/worker.ts).
const WASM_PKG = new URL("../../wasm/prover/pkg/", import.meta.url).pathname;
const WASM_PUBLIC = new URL("./public/tlsnc-wasm/", import.meta.url).pathname;
if (!existsSync(WASM_PKG)) throw new Error("build the prover first: wasm/prover/build.sh");
rmSync(WASM_PUBLIC, { recursive: true, force: true });
cpSync(WASM_PKG, WASM_PUBLIC, { recursive: true });

export default defineConfig({
  // Extension pages load from chrome-extension://<id>/, so relative paths work too.
  base: "./",
  resolve: { dedupe: ["@cashu/cashu-ts"] },
  worker: { format: "es" },
  build: {
    target: "es2022",
    // Chrome Web Store reviewers read the code; keep it readable.
    minify: false,
    modulePreload: false,
    rollupOptions: {
      input: {
        app: "app.html",
        notarize: "notarize.html",
        background: "src/background.ts",
      },
      output: {
        entryFileNames: (c) => (c.name === "background" ? "background.js" : "assets/[name]-[hash].js"),
      },
    },
  },
});
