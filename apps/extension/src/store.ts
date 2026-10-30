/** chrome.storage.local as the wallet's Store, plus the extension's settings. */
import type { Info } from "@tlsnc/client";
import { CashuWallet, type Store } from "./wallet.js";

export const chromeStore: Store = {
  async get<T>(key: string) {
    const r = await chrome.storage.local.get(key);
    return r[key] as T | undefined;
  },
  async set(key: string, value: unknown) {
    if (value === undefined) await chrome.storage.local.remove(key);
    else await chrome.storage.local.set({ [key]: value });
  },
};

export const wallet = new CashuWallet(chromeStore);

export interface Settings {
  notary: string;
  /** Refuse a notary whose key differs (hex); empty: trust what /info says. */
  expectedKey: string;
}

export async function settings(): Promise<Settings> {
  const s = await chromeStore.get<Partial<Settings>>("settings");
  return { notary: s?.notary ?? "", expectedKey: s?.expectedKey ?? "" };
}

/** The configured notary URL. There is no public default: the user runs or picks one. */
export function requireNotary(s: Settings): string {
  if (!s.notary) throw new Error("Set a notary URL in Settings first. There is no public notary; run your own.");
  return s.notary;
}

export async function saveSettings(s: Settings): Promise<void> {
  await chromeStore.set("settings", { notary: s.notary.trim().replace(/\/+$/, ""), expectedKey: s.expectedKey.trim() });
}

/** The notary's /info, cached for a few minutes so the popup opens fast offline-ish. */
export async function notaryInfo(force = false): Promise<Info> {
  const s = await settings();
  const cached = await chromeStore.get<{ at: number; notary: string; info: Info }>("infoCache");
  if (!force && cached && cached.notary === s.notary && Date.now() - cached.at < 5 * 60_000) return cached.info;
  const resp = await fetch(`${requireNotary(s)}/info`);
  if (!resp.ok) throw new Error(`${s.notary}/info: HTTP ${resp.status}`);
  const info = (await resp.json()) as Info;
  if (s.expectedKey && info.notary_key.key.toLowerCase() !== s.expectedKey.toLowerCase()) {
    throw new Error(`notary key is ${info.notary_key.key}, settings expect ${s.expectedKey}`);
  }
  await chromeStore.set("infoCache", { at: Date.now(), notary: s.notary, info });
  return info;
}
