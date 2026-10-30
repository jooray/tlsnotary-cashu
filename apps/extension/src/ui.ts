/** Small DOM helpers shared by the pages. */
import type { Verified } from "@tlsnc/verify";

export const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> & { class?: string } = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  const { class: cls, ...rest } = props;
  if (cls) e.className = cls;
  Object.assign(e, rest);
  e.append(...children);
  return e;
}

export function say(target: HTMLElement, text: string, kind: "ok" | "error" | "" = ""): void {
  target.textContent = text;
  target.className = `msg ${kind}`;
}

export const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));

export const when = (unix: number) => new Date(unix * 1000).toLocaleString();

export const host = (url: string) => {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
};

export async function copy(text: string, button?: HTMLButtonElement): Promise<void> {
  await navigator.clipboard.writeText(text);
  if (button) {
    const old = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => (button.textContent = old), 1200);
  }
}

export function download(bytes: Uint8Array, name: string): void {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: "application/octet-stream" }));
  const a = el("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** Renders a verified presentation: server, time, revealed request and response. */
export function renderVerified(v: Verified): HTMLElement {
  const box = el("div", { class: "verified" });
  box.append(
    el("p", { class: "ok" }, `Verified: ${v.server_name}`),
    el("p", { class: "hint" }, `Connection at ${when(v.time)}; notary key ${v.notary_key.key.slice(0, 16)}…`),
    el("h3", {}, `Request (hidden bytes shown as ${v.mask})`),
    el("pre", {}, v.sent),
    el("h3", {}, "Response"),
    el("pre", {}, v.received),
  );
  return box;
}
