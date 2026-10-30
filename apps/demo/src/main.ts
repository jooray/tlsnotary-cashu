import "./style.css";
import { TlsnClient, callbackPayer, type Info, type Mode, type Notarized, type PaymentRequestInfo, type RevealSpec } from "@tlsnc/client";
import { fetchNotaryKeys, verify, type NotaryKey } from "@tlsnc/verify";
import { VERSION, startUpdates, toast } from "./update";

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

// The demo is served by the notary itself, so the notary is this origin.
const NOTARY = new URLSearchParams(location.search).get("notary") ?? location.origin;
const client = new TlsnClient({ notary: NOTARY, wasmUrl: `${import.meta.env.BASE_URL}tlsnc-wasm/tlsnc_wasm.js` });
let info: Info | undefined;
let running = false;
let last: Notarized | undefined;

$("version").textContent = VERSION;
startUpdates(() => running);

// Tabs
for (const b of document.querySelectorAll<HTMLButtonElement>(".tab")) {
  b.onclick = () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t === b));
    document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === b.dataset.tab));
  };
}

$("method").onchange = () => {
  $("body-label").hidden = ["GET", "DELETE"].includes($<HTMLSelectElement>("method").value);
};

client
  .info()
  .then((i) => {
    info = i;
    const prices = i.tiers.map((t) => `${t.id} ≤${(t.max_sent / 1024).toFixed(0)} KiB: ${t.price.notary} sat`).join(" · ");
    $("notary-line").textContent = `${i.name} · key ${i.notary_key.key.slice(0, 16)}… · ${prices}`;
  })
  .catch((e) => ($("notary-line").textContent = `Notary unavailable: ${e.message}`));

if (!crossOriginIsolated) {
  $("notary-line").insertAdjacentHTML(
    "afterend",
    `<p class="error">This page is not cross-origin isolated (COOP/COEP headers missing), so the prover cannot run here.</p>`,
  );
}

function parseHeaders(text: string): [string, string][] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const i = l.indexOf(":");
      if (i < 1) throw new Error(`bad header line: ${l}`);
      return [l.slice(0, i).trim(), l.slice(i + 1).trim()] as [string, string];
    });
}

function request() {
  const method = $<HTMLSelectElement>("method").value;
  return {
    url: $<HTMLInputElement>("url").value.trim(),
    method,
    headers: parseHeaders($<HTMLTextAreaElement>("headers").value),
    body: $("body-label").hidden ? undefined : $<HTMLTextAreaElement>("body").value,
  };
}

/** Shows the payment card and resolves with the pasted token. */
function askToPay(req: PaymentRequestInfo): Promise<string> {
  $("pay-card").hidden = false;
  $("pay-amount").textContent = String(req.amount);
  $("pay-mints").innerHTML = req.mints.map((m) => `<li>${escape(m)}</li>`).join("");
  $("pay-creq").textContent = req.encoded;
  $("copy-creq").onclick = () => navigator.clipboard.writeText(req.encoded).then(() => toast("Copied"));
  const token = $<HTMLTextAreaElement>("pay-token");
  token.value = "";
  token.focus();
  return new Promise((resolve, reject) => {
    $("pay-ok").onclick = () => {
      const t = token.value.trim();
      if (!t.startsWith("cashu")) return toast("Paste a Cashu token (cashuB…)");
      $("pay-card").hidden = true;
      resolve(t);
    };
    $("pay-cancel").onclick = () => {
      $("pay-card").hidden = true;
      reject(new Error("cancelled"));
    };
  });
}

let reuseTicket: string | undefined;

$("req-form").onsubmit = async (ev) => {
  ev.preventDefault();
  if (running) return;
  const go = $<HTMLButtonElement>("go");
  $("error").hidden = true;
  $("result-card").hidden = true;
  const mode = (document.querySelector<HTMLInputElement>('input[name="mode"]:checked')!.value as Mode) ?? "bridge";
  let req;
  try {
    req = request();
    const q = await client.quote(req, mode);
    $("quote").textContent = `Tier ${q.tier.id} · request ${q.requestBytes} B · ${q.price} sat`;
  } catch (e) {
    return showError(e);
  }

  running = true;
  go.disabled = true;
  $("progress-card").hidden = false;
  document.querySelectorAll("#steps li").forEach((li) => li.classList.remove("active", "done"));
  const mark = (step: string) => {
    const items = [...document.querySelectorAll<HTMLLIElement>("#steps li")];
    const idx = items.findIndex((li) => li.dataset.step === step);
    items.forEach((li, i) => {
      li.classList.toggle("done", i < idx);
      li.classList.toggle("active", i === idx);
    });
  };
  try {
    last = await client.notarize({
      request: req,
      mode,
      ticket: reuseTicket,
      pay: callbackPayer(askToPay),
      onStep: mark,
      onTicket: (t) => {
        $("ticket-line").hidden = false;
        $("ticket-line").textContent = `Ticket valid until ${new Date(t.expires_at * 1000).toLocaleTimeString()}, ${t.attempts} attempts.`;
      },
    });
    reuseTicket = undefined;
    document.querySelectorAll("#steps li").forEach((li) => {
      li.classList.remove("active");
      li.classList.add("done");
    });
    showResult(last);
  } catch (e) {
    const t = (e as { ticket?: string }).ticket;
    if (t) {
      reuseTicket = t;
      $("ticket-line").hidden = false;
      $("ticket-line").textContent = "The ticket is still valid: submitting again reuses it without paying.";
    }
    showError(e);
  } finally {
    running = false;
    go.disabled = false;
  }
};

function showError(e: unknown) {
  $("progress-card").hidden = false;
  const el = $("error");
  el.hidden = false;
  el.textContent = e instanceof Error ? e.message : String(e);
}

function showResult(n: Notarized) {
  $("result-card").hidden = false;
  $("res-status").textContent = String(n.response.status);
  $("res-size").textContent = `${n.response.body.length} bytes`;
  const text = new TextDecoder().decode(n.response.body);
  let pretty = text;
  try {
    pretty = JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    // not JSON
  }
  $("res-body").textContent = pretty.slice(0, 20_000);
  const defaults = ["date", "content-type"];
  $("res-headers").innerHTML = n.response.headers
    .map(([k]) => {
      const checked = defaults.includes(k.toLowerCase()) ? "checked" : "";
      return `<label><input type="checkbox" value="${escape(k)}" ${checked}/> ${escape(k)}</label>`;
    })
    .join("");
}

function revealSpec(): RevealSpec {
  const headers = [...document.querySelectorAll<HTMLInputElement>("#res-headers input:checked")].map((i) => i.value);
  const which = document.querySelector<HTMLInputElement>('input[name="body-reveal"]:checked')!.value;
  const paths = $<HTMLInputElement>("json-paths")
    .value.split(",")
    .map((p) => p.trim())
    .filter(Boolean);
  const body = which === "json" ? { json_paths: paths } : (which as "all" | "none");
  return { response: { headers, body } };
}

$("make-presentation").onclick = async () => {
  if (!last) return;
  try {
    const p = await client.present(last, revealSpec());
    download(p, `${new URL(request().url).hostname}.presentation`);
    toast("Presentation downloaded");
  } catch (e) {
    toast(e instanceof Error ? e.message : String(e), 6000);
  }
};

$("dl-attestation").onclick = () => {
  if (!last) return;
  download(last.attestation, "session.attestation");
  download(last.secrets, "session.secrets");
};

// Verify tab
$("v-go").onclick = async () => {
  $("v-error").hidden = true;
  $("v-result").hidden = true;
  try {
    const file = $<HTMLInputElement>("v-file").files?.[0];
    if (!file) throw new Error("choose a presentation file");
    const typed = $<HTMLTextAreaElement>("v-keys")
      .value.split("\n")
      .map((k) => k.trim())
      .filter(Boolean)
      .map((key): NotaryKey => ({ alg: "k256", key }));
    const keys = typed.length ? typed : await fetchNotaryKeys(NOTARY);
    const v = await verify(new Uint8Array(await file.arrayBuffer()), keys);
    $("v-result").hidden = false;
    $("v-title").textContent = `✓ Valid: data from ${v.server_name}`;
    $("v-meta").textContent = `Connection at ${new Date(v.time * 1000).toISOString()} · notary key ${v.notary_key.key.slice(0, 16)}…`;
    $("v-sent").textContent = v.sent;
    $("v-recv").textContent = v.received;
  } catch (e) {
    $("v-error").hidden = false;
    $("v-error").textContent = e instanceof Error ? e.message : String(e);
  }
};

function download(bytes: Uint8Array, name: string) {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: "application/octet-stream" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function escape(s: string) {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}
