/**
 * Notarizes one page: builds the request (optionally with the tab's
 * cookies), pays the ticket from the wallet, runs MPC-TLS through the
 * notary, and turns the attestation into a presentation.
 *
 * The page is cross-origin isolated by the manifest (COOP/COEP), which the
 * prover's WebAssembly threads need.
 */
import { type HttpRequestSpec, type Mode, type Notarized, NotaryError, type RevealSpec, TlsnClient } from "@tlsnc/client";
import { fetchNotaryKeys, verify } from "@tlsnc/verify";
import { requireNotary, settings, wallet } from "./store.js";
import { $, download, el, errText, host, renderVerified, say } from "./ui.js";
import type { HistoryEntry } from "./wallet.js";
import "./style.css";

/** Header values the presentation hides unless the user allows it (as crates/client does). */
const CREDENTIALS = ["authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"];
const STEPS: Record<string, string> = {
  pay: "Paying the notary",
  setup: "Setting up MPC with the notary",
  request: "Sending the request",
  prove: "Proving the transcript",
  attest: "Getting the signed attestation",
};

const params = new URLSearchParams(location.search);
const urlInput = $<HTMLInputElement>("url");
urlInput.value = params.get("url") ?? "";

let client: TlsnClient;
let result: (Notarized & { request: HttpRequestSpec }) | undefined;
let ticket: string | undefined;

async function makeClient() {
  const s = await settings();
  client = new TlsnClient({
    notary: requireNotary(s),
    expectedKey: s.expectedKey || undefined,
    wasmUrl: chrome.runtime.getURL("tlsnc-wasm/tlsnc_wasm.js"),
  });
}

async function showBalance() {
  const b = await wallet.balances();
  $("balance").textContent = Object.values(b).reduce((s, n) => s + n, 0).toLocaleString();
}

function target(): URL {
  const u = new URL(urlInput.value.trim());
  if (u.protocol !== "https:") throw new Error("only https:// pages can be notarized");
  return u;
}

const cookieBox = $<HTMLInputElement>("use-cookies");
cookieBox.onchange = async () => {
  if (!cookieBox.checked) return void requote();
  try {
    const origin = target().origin;
    // Asked at the moment of use, for this site only.
    const granted = await chrome.permissions.request({ permissions: ["cookies"], origins: [`${origin}/*`] });
    cookieBox.checked = granted;
  } catch (e) {
    cookieBox.checked = false;
    say($("go-msg"), errText(e), "error");
  }
  void requote();
};

async function buildRequest(): Promise<HttpRequestSpec> {
  const url = target();
  const headers: [string, string][] = [
    ["User-Agent", navigator.userAgent],
    ["Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"],
    ["Accept-Language", navigator.languages.join(",") || "en"],
  ];
  if (cookieBox.checked) {
    const cookies = await chrome.cookies.getAll({ url: url.href });
    if (cookies.length) headers.push(["Cookie", cookies.map((c) => `${c.name}=${c.value}`).join("; ")]);
  }
  for (const line of $<HTMLTextAreaElement>("headers").value.split("\n")) {
    const i = line.indexOf(":");
    if (i > 0) headers.push([line.slice(0, i).trim(), line.slice(i + 1).trim()]);
  }
  return { url: url.href, method: "GET", headers };
}

const mode = () => $<HTMLSelectElement>("mode").value as Mode;

let quoteSeq = 0;
async function requote() {
  const seq = ++quoteSeq;
  const go = $<HTMLButtonElement>("go");
  try {
    const q = await client.quote(await buildRequest(), mode());
    if (seq !== quoteSeq) return;
    $("quote").textContent = `tier ${q.tier.id}, request ${q.requestBytes} B`;
    const info = await client.info();
    const balances = await wallet.balances();
    const usable = Math.max(0, ...info.mints.map((m) => balances[m.replace(/\/+$/, "")] ?? 0));
    if (!ticket && usable < q.price) {
      // Mint fees come on top; the wallet says so if they do not fit.
      go.textContent = `Needs ${q.price} sat`;
      go.disabled = true;
      $("quote").textContent += ` · top up the wallet (${usable} sat at an accepted mint)`;
      return;
    }
    go.textContent = ticket ? "Notarize" : `Pay ${q.price} sat & notarize`;
    go.disabled = false;
  } catch (e) {
    if (seq !== quoteSeq) return;
    $("quote").textContent = errText(e);
    go.disabled = true;
  }
}
let typing: ReturnType<typeof setTimeout>;
urlInput.oninput = $("headers").oninput = () => {
  clearTimeout(typing);
  typing = setTimeout(requote, 400);
};
$("mode").onchange = () => void requote();

function step(s: string) {
  const list = $("steps");
  for (const li of list.querySelectorAll("li")) li.classList.add("done");
  list.append(el("li", {}, STEPS[s] ?? s));
}

async function run() {
  const msg = $("go-msg");
  const go = $<HTMLButtonElement>("go");
  go.disabled = true;
  go.dataset.busy = "1";
  $("retry").hidden = true;
  $("steps").replaceChildren();
  say(msg, "");
  let payment: HistoryEntry | undefined;
  let gotTicket = false;
  try {
    const request = await buildRequest();
    const n = await client.notarize({
      request,
      mode: mode(),
      ticket,
      pay: async (req) => {
        const { token, entry } = await wallet.pay(req, `${host(request.url)} (${req.description ?? "ticket"})`);
        payment = entry;
        return token;
      },
      onStep: step,
      onTicket: (t) => {
        gotTicket = true;
        ticket = t.ticket;
        // The notary redeemed the token: nothing to take back any more.
        if (payment) void wallet.updateHistory(payment.id, { token: undefined, ticket: t.ticket });
      },
    });
    for (const li of $("steps").querySelectorAll("li")) li.classList.add("done");
    ticket = undefined;
    result = { ...n, request };
    say(msg, "Notarized.", "ok");
    showResult();
  } catch (e) {
    let text = errText(e);
    if (payment && !gotTicket) text += await recover(payment, e);
    say(msg, text, "error");
    $("retry").hidden = !ticket;
  } finally {
    delete go.dataset.busy;
    go.disabled = false;
    await showBalance();
    void requote();
  }
}

/** The ticket was not issued: collect the notary's refund, or take the token back. */
async function recover(payment: HistoryEntry, e: unknown): Promise<string> {
  const refund = e instanceof NotaryError ? (e.body as { refund?: string } | undefined)?.refund : undefined;
  try {
    if (refund) {
      const r = await wallet.receive(refund, "refund", "notary refund");
      await wallet.updateHistory(payment.id, { token: undefined });
      return ` The notary refunded ${r.amount} sat.`;
    }
    if (await wallet.tokenUnspent(payment.id)) {
      const n = await wallet.reclaim(payment.id);
      return ` The payment was not used; ${n} sat are back in the wallet.`;
    }
  } catch (err) {
    return ` The payment token is in History (${errText(err)}).`;
  }
  return " The payment token is in History.";
}

$("go").onclick = () => void run();
$("retry").onclick = () => void run();

function showResult() {
  const n = result!;
  $("result").hidden = false;
  $("reveal").hidden = false;
  $("status").textContent = `HTTP ${n.response.status} from ${host(n.request.url)}`;
  const text = new TextDecoder().decode(n.response.body);
  let shown = text;
  try {
    shown = JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    // not JSON
  }
  $("body").textContent = shown.length > 50_000 ? `${shown.slice(0, 50_000)}\n… (${text.length} bytes)` : shown;
  const isJson = /json/i.test(n.response.headers.find(([k]) => k.toLowerCase() === "content-type")?.[1] ?? "");
  if (isJson) (document.querySelector('input[name="body"][value="json"]') as HTMLInputElement).click();

  const reqNames = ["host", ...(n.request.headers ?? []).map(([k]) => k.toLowerCase())];
  renderChecks($("rv-req-headers"), [...new Set(reqNames)], ["host"]);
  const resNames = [...new Set(n.response.headers.map(([k]) => k.toLowerCase()))];
  renderChecks($("rv-res-headers"), resNames, ["date", "content-type"]);
  $("verified").replaceChildren();
}

function renderChecks(box: HTMLElement, names: string[], defaults: string[]) {
  box.replaceChildren(
    ...names.map((name) => {
      const input = el("input", { type: "checkbox", value: name, checked: defaults.includes(name) });
      const cred = CREDENTIALS.includes(name);
      if (cred) input.dataset.credential = "1";
      input.disabled = cred && !$<HTMLInputElement>("rv-creds").checked;
      return el("label", { class: `check${cred ? " danger" : ""}` }, input, ` ${name}`);
    }),
  );
}

$<HTMLInputElement>("rv-creds").onchange = (ev) => {
  const on = (ev.target as HTMLInputElement).checked;
  for (const i of document.querySelectorAll<HTMLInputElement>("input[data-credential]")) {
    i.disabled = !on;
    if (!on) i.checked = false;
  }
};
for (const r of document.querySelectorAll<HTMLInputElement>('input[name="body"]')) {
  r.onchange = () => ($("rv-json").hidden = r.value !== "json" || !r.checked);
}

function revealSpec(): RevealSpec {
  const ticked = (id: string) => [...document.querySelectorAll<HTMLInputElement>(`#${id} input:checked`)].map((i) => i.value);
  const kind = (document.querySelector('input[name="body"]:checked') as HTMLInputElement).value;
  const paths = $<HTMLTextAreaElement>("rv-json").value.split(/[\s,]+/).filter(Boolean);
  if (kind === "json" && !paths.length) throw new Error("list at least one JSON path, or reveal all or nothing");
  return {
    request: { target: $<HTMLInputElement>("rv-target").checked, headers: ticked("rv-req-headers"), body: false },
    response: {
      headers: ticked("rv-res-headers"),
      body: kind === "all" ? "all" : kind === "none" ? "none" : { json_paths: paths },
    },
    allow_credentials: $<HTMLInputElement>("rv-creds").checked,
  };
}

const fileBase = () => `${host(result!.request.url)}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}`;

$("present").onclick = async () => {
  const msg = $("present-msg");
  try {
    say(msg, "Building…");
    const p = await client.present(result!, revealSpec());
    download(p, `${fileBase()}.presentation`);
    say(msg, "Downloaded. Checking it…");
    const keys = await fetchNotaryKeys(requireNotary(await settings()));
    $("verified").replaceChildren(renderVerified(await verify(p, keys)));
    say(msg, "Downloaded and verified.", "ok");
  } catch (e) {
    say(msg, errText(e), "error");
  }
};

$("dl-attestation").onclick = () => {
  // The names the CLI expects: `tlsnc present PREFIX` reads PREFIX.attestation and PREFIX.secrets.
  download(result!.attestation, `${fileBase()}.attestation`);
  download(result!.secrets, `${fileBase()}.secrets`);
};

chrome.storage.onChanged.addListener((changes) => {
  if ("wallet.proofs" in changes) {
    void showBalance();
    if (!$<HTMLButtonElement>("go").dataset.busy) void requote();
  }
});

void (async () => {
  if (!crossOriginIsolated) {
    say($("go-msg"), "This page is not cross-origin isolated; the prover cannot run.", "error");
    return;
  }
  await makeClient();
  await showBalance();
  if (urlInput.value) void requote();
  else $<HTMLButtonElement>("go").disabled = true;
})();
