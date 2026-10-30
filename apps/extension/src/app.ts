/** The wallet: popup and full tab (same page). */
import { fetchNotaryKeys, verify } from "@tlsnc/verify";
import { renderSVG } from "uqr";
import { notaryInfo, requireNotary, saveSettings, settings, wallet } from "./store.js";
import { $, copy, el, errText, host, renderVerified, say, when } from "./ui.js";
import { CashuWallet, type HistoryEntry, type PendingQuote, normalizeMint, tokenMint } from "./wallet.js";
import "./style.css";

const isPopup = new URLSearchParams(location.search).has("popup");
document.body.classList.toggle("popup", isPopup);

let accepted: string[] = [];
const infoLoaded = loadInfo();

for (const b of document.querySelectorAll<HTMLButtonElement>(".tab")) {
  b.onclick = () => showTab(b.dataset.tab!);
}
function showTab(id: string) {
  for (const b of document.querySelectorAll<HTMLButtonElement>(".tab")) b.classList.toggle("active", b.dataset.tab === id);
  for (const p of document.querySelectorAll(".panel")) p.classList.toggle("active", p.id === id);
  if (id === "history") void renderHistory();
  if (id === "backup") void renderBackup();
  if (id === "settings") void renderSettings();
}
if (location.hash) showTab(location.hash.slice(1));
window.onhashchange = () => showTab(location.hash.slice(1) || "wallet");

function fillMintSelect(select: HTMLSelectElement, mints: string[]) {
  const current = select.value;
  select.replaceChildren(...mints.map((m) => el("option", { value: m, textContent: host(m) })));
  if (mints.includes(current)) select.value = current;
}

async function renderBalances() {
  const balances = await wallet.balances();
  const total = Object.values(balances).reduce((s, n) => s + n, 0);
  $("total").textContent = total.toLocaleString();
  $("mints").replaceChildren(
    ...Object.entries(balances).map(([mint, n]) => {
      const ok = accepted.length === 0 || accepted.includes(mint);
      return el(
        "li",
        {},
        el("span", {}, host(mint)),
        el("span", { class: ok ? "" : "warn", title: ok ? "" : "The notary does not accept this mint" }, `${n} sat${ok ? "" : " ⚠"}`),
      );
    }),
  );
  const spendable = Object.keys(balances);
  fillMintSelect($("send-mint"), spendable);
  fillMintSelect($("export-mint"), spendable);
  void chrome.action?.setBadgeText({ text: "" });
}

async function loadInfo() {
  try {
    const info = await notaryInfo();
    accepted = info.mints.map(normalizeMint);
    fillMintSelect($("receive-mint"), accepted);
    const cheapest = Math.min(...info.tiers.map((t) => t.price.notary));
    $("notarize-hint").textContent = `${info.name}: from ${cheapest} sat per page.`;
  } catch (e) {
    $("notarize-hint").textContent = `Notary unreachable: ${errText(e)}`;
  }
}

$("notarize").onclick = async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = isPopup ? tab?.url : undefined;
  const page = chrome.runtime.getURL(`notarize.html${url ? `?url=${encodeURIComponent(url)}` : ""}`);
  await chrome.tabs.create({ url: page });
  if (isPopup) window.close();
};
$("open-tab").hidden = !isPopup;
$("open-tab").onclick = async () => {
  await chrome.tabs.create({ url: chrome.runtime.getURL("app.html") });
  window.close();
};

// Receive: a number makes a Lightning invoice, anything else is a token.
$("receive").onclick = async () => {
  const msg = $("receive-msg");
  const value = $<HTMLTextAreaElement>("receive-input").value.trim();
  if (!value) return;
  try {
    if (/^[1-9]\d*$/.test(value)) {
      const mint = $<HTMLSelectElement>("receive-mint").value;
      if (!mint) throw new Error("no mint to choose (is the notary reachable?)");
      say(msg, "Asking the mint for an invoice…");
      await wallet.requestInvoice(mint, Number(value));
      void chrome.runtime.sendMessage({ type: "watch-quotes" }).catch(() => undefined);
      say(msg, "Pay the invoice below; the wallet mints it as soon as it is paid, even after this popup closes.");
    } else {
      const mint = tokenMint(value);
      if (accepted.length && !accepted.includes(mint) && !confirm(`The notary does not accept ${mint}. Receive anyway?`)) return;
      say(msg, "Redeeming…");
      const r = await wallet.receive(value);
      say(msg, `Received ${r.amount} sat at ${host(r.mint)}.`, "ok");
    }
    $<HTMLTextAreaElement>("receive-input").value = "";
  } catch (e) {
    say(msg, errText(e), "error");
  }
  await Promise.all([renderBalances(), renderQuotes()]);
};

async function renderQuotes() {
  const qs = await wallet.pendingQuotes();
  $("quotes").replaceChildren(...qs.map(quoteCard));
}

function quoteCard(q: PendingQuote): HTMLElement {
  const qr = el("div", { class: "qr" });
  qr.innerHTML = renderSVG(`lightning:${q.request}`, { ecc: "L", border: 1 });
  const copyBtn = el("button", { textContent: "Copy invoice" });
  copyBtn.onclick = () => copy(q.request, copyBtn);
  const cancel = el("button", { class: "ghost", textContent: "Forget" });
  cancel.onclick = async () => {
    await wallet.cancelQuote(q.quote);
    await renderQuotes();
  };
  return el(
    "div",
    { class: "quote" },
    el("p", {}, `${q.amount} sat at ${host(q.mint)}`, q.expiry ? el("small", {}, ` · expires ${when(q.expiry)}`) : ""),
    qr,
    el("code", { class: "break" }, q.request),
    el("div", { class: "row end" }, cancel, copyBtn),
  );
}

let polling = false;
async function pollQuotes() {
  if (polling) return;
  polling = true;
  try {
    const minted = await wallet.checkQuotes();
    if (minted.length) {
      say($("receive-msg"), `Received ${minted.map((m) => `${m.amount} sat`).join(", ")} over Lightning.`, "ok");
      await renderBalances();
    }
    await renderQuotes();
  } catch (e) {
    console.warn(e);
  } finally {
    polling = false;
  }
}

$("send").onclick = async () => {
  const msg = $("send-msg");
  const amount = Number($<HTMLInputElement>("send-amount").value);
  const mint = $<HTMLSelectElement>("send-mint").value;
  if (!amount || !mint) return;
  try {
    say(msg, "Creating token…");
    const { token } = await wallet.send(mint, amount);
    const out = $<HTMLTextAreaElement>("send-token");
    out.value = token;
    out.hidden = false;
    $("send-copy").hidden = false;
    say(msg, "Token created. Until someone redeems it, History can take it back.", "ok");
  } catch (e) {
    say(msg, errText(e), "error");
  }
  await renderBalances();
};
$("send-copy").onclick = (ev) => copy($<HTMLTextAreaElement>("send-token").value, ev.currentTarget as HTMLButtonElement);

const KIND: Record<HistoryEntry["kind"], string> = {
  receive: "Received",
  mint: "Lightning",
  send: "Sent",
  pay: "Notarization",
  refund: "Refund",
  restore: "Restored",
  reclaim: "Taken back",
};

async function renderHistory() {
  const h = await wallet.history();
  const list = $("history-list");
  if (!h.length) {
    list.replaceChildren(el("li", { class: "hint" }, "Nothing yet."));
    return;
  }
  list.replaceChildren(
    ...h.map((e) => {
      const li = el(
        "li",
        {},
        el("div", {}, el("strong", {}, KIND[e.kind]), " ", el("small", {}, `${when(e.time)} · ${host(e.mint)}`)),
        el("div", { class: e.amount < 0 ? "out" : "in" }, `${e.amount > 0 ? "+" : ""}${e.amount} sat`),
      );
      const detail = [e.note, e.fee ? `fee ${e.fee} sat` : "", e.ticket ? `ticket ${e.ticket.slice(0, 12)}…` : ""]
        .filter(Boolean)
        .join(" · ");
      if (detail) li.append(el("small", { class: "detail" }, detail));
      if (e.token) {
        const back = el("button", { class: "ghost", textContent: "Take back" });
        back.onclick = async () => {
          try {
            back.disabled = true;
            if (!(await wallet.tokenUnspent(e.id))) {
              await wallet.updateHistory(e.id, { token: undefined });
              back.textContent = "Already redeemed";
              return;
            }
            const n = await wallet.reclaim(e.id);
            back.textContent = `Took back ${n} sat`;
            await renderBalances();
          } catch (err) {
            back.textContent = errText(err);
          }
        };
        const cp = el("button", { class: "ghost", textContent: "Copy token" });
        cp.onclick = () => copy(e.token!, cp);
        li.append(el("div", { class: "row end" }, cp, back));
      }
      return li;
    }),
  );
}

async function renderBackup() {
  const words = await wallet.mnemonic();
  const box = $("words");
  box.replaceChildren(...words.split(" ").map((w, i) => el("span", {}, el("small", {}, `${i + 1}`), w)));
  box.onclick = () => box.classList.remove("blurred");
  $("words-copy").onclick = (ev) => copy(words, ev.currentTarget as HTMLButtonElement);
  const mintsBox = $<HTMLTextAreaElement>("restore-mints");
  if (!mintsBox.value) {
    await infoLoaded;
    mintsBox.value = [...new Set([...accepted, ...Object.keys(await wallet.balances())])].join("\n");
  }
}

$("restore").onclick = async () => {
  const msg = $("restore-msg");
  const words = $<HTMLTextAreaElement>("restore-words").value;
  if (!CashuWallet.validMnemonic(words)) return say(msg, "Those are not valid BIP-39 words.", "error");
  const mints = $<HTMLTextAreaElement>("restore-mints").value.split(/\s+/).filter(Boolean);
  if (!confirm("Replace this wallet's backup words? Keep a copy of the current words if this wallet holds anything.")) return;
  try {
    const found = await wallet.restore(words, mints, (m) => say(msg, `Scanning ${host(m)}…`));
    const lines = Object.entries(found).map(([m, n]) => `${host(m)}: ${n < 0 ? "unreachable" : `${n} sat`}`);
    say(msg, lines.length ? `Restored. ${lines.join(", ")}` : "Restored the words; no unspent proofs found.", "ok");
    $<HTMLTextAreaElement>("restore-words").value = "";
    await Promise.all([renderBalances(), renderBackup()]);
  } catch (e) {
    say(msg, errText(e), "error");
  }
};

$("export").onclick = async () => {
  const mint = $<HTMLSelectElement>("export-mint").value;
  if (!mint) return;
  try {
    const token = await wallet.exportMint(mint);
    const out = $<HTMLTextAreaElement>("export-token");
    out.value = token;
    out.hidden = false;
    await copy(token);
    say($("export-msg"), "Copied. The token is also kept in History until redeemed.", "ok");
  } catch (e) {
    say($("export-msg"), errText(e), "error");
  }
  await renderBalances();
};
$("sync").onclick = async () => {
  try {
    const n = await wallet.sync();
    say($("export-msg"), n ? `Dropped ${n} sat of spent proofs.` : "All proofs are unspent.", "ok");
  } catch (e) {
    say($("export-msg"), errText(e), "error");
  }
  await renderBalances();
};

async function renderSettings() {
  const s = await settings();
  $<HTMLInputElement>("set-notary").value = s.notary;
  $<HTMLInputElement>("set-key").value = s.expectedKey;
  try {
    const info = await notaryInfo(true);
    $("info-name").textContent = info.name;
    $("info-desc").textContent = info.description;
    const kib = (n: number) => (n >= 1 << 20 ? `${n / (1 << 20)} MiB` : `${n / 1024} KiB`);
    $("info-tiers").replaceChildren(
      ...info.tiers.map((t) =>
        el("tr", {}, el("td", {}, t.id), el("td", {}, `≤ ${kib(t.max_sent)}`), el("td", {}, `≤ ${kib(t.max_recv)}`), el("td", {}, `${t.price.notary} sat`)),
      ),
    );
    $("info-mints").replaceChildren(...info.mints.map((m) => el("li", {}, m)));
    $("info-key").textContent = `${info.notary_key.alg} ${info.notary_key.key}`;
  } catch (e) {
    $("info-name").textContent = "Notary unreachable";
    $("info-desc").textContent = errText(e);
  }
}

$("save-settings").onclick = async () => {
  const notary = $<HTMLInputElement>("set-notary").value.trim();
  try {
    new URL(notary);
  } catch {
    return say($("settings-msg"), "Not a URL.", "error");
  }
  await saveSettings({ notary, expectedKey: $<HTMLInputElement>("set-key").value });
  say($("settings-msg"), "Saved.", "ok");
  await Promise.all([renderSettings(), loadInfo()]);
};

$<HTMLInputElement>("verify-file").onchange = async (ev) => {
  const file = (ev.target as HTMLInputElement).files?.[0];
  const out = $("verify-out");
  if (!file) return;
  try {
    const keys = await fetchNotaryKeys(requireNotary(await settings()));
    out.replaceChildren(renderVerified(await verify(new Uint8Array(await file.arrayBuffer()), keys)));
  } catch (e) {
    out.replaceChildren(el("p", { class: "msg error" }, `Not valid: ${errText(e)}`));
  }
};

// Other pages (notarize, background) change the wallet too.
chrome.storage.onChanged.addListener((changes) => {
  if ("wallet.proofs" in changes) void renderBalances();
  if ("wallet.quotes" in changes) void renderQuotes();
  if ("wallet.history" in changes && $("history").classList.contains("active")) void renderHistory();
});

void (async () => {
  await infoLoaded;
  await Promise.all([renderBalances(), renderQuotes()]);
  await pollQuotes();
  setInterval(() => void (async () => (await wallet.pendingQuotes()).length && pollQuotes())(), 2500);
})();
