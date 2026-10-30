/**
 * Mints paid Lightning invoices while no extension page is open (the popup
 * closes as soon as the user switches to their Lightning wallet).
 */
import { wallet } from "./store.js";

const ALARM = "tlsnc-quotes";

async function check(): Promise<void> {
  const pending = await wallet.pendingQuotes();
  if (!pending.length) {
    await chrome.alarms.clear(ALARM);
    return;
  }
  const minted = await wallet.checkQuotes();
  const total = minted.reduce((s, m) => s + m.amount, 0);
  if (total) await chrome.action.setBadgeText({ text: "+" });
}

chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === ALARM) void check().catch((e) => console.warn("quote check:", e));
});

// Pages announce a new invoice; poll every 30 s until it is paid or expires.
chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "watch-quotes") void chrome.alarms.create(ALARM, { periodInMinutes: 0.5 });
});

chrome.runtime.onStartup.addListener(() => void check());
