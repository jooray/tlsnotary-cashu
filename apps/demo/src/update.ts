/**
 * New-version detection: the build writes version.json; we poll it and, on
 * a mismatch, activate the new service worker and reload on our own. The
 * user never has to refresh.
 */
declare const __APP_VERSION__: string;
export const VERSION = __APP_VERSION__;

const CHECK_EVERY_MS = 60_000;
const NOTICE_KEY = "tlsnc-updated-to";

function toast(text: string, ms = 4000) {
  const el = document.getElementById("toast")!;
  el.textContent = text;
  el.hidden = false;
  setTimeout(() => (el.hidden = true), ms);
}

async function latestVersion(): Promise<string | undefined> {
  try {
    const resp = await fetch(`./version.json?t=${Date.now()}`, { cache: "no-store" });
    if (!resp.ok) return undefined;
    return ((await resp.json()) as { version: string }).version;
  } catch {
    return undefined;
  }
}

let reloading = false;
function reloadInto(version: string) {
  if (reloading) return;
  reloading = true;
  try {
    sessionStorage.setItem(NOTICE_KEY, version);
  } catch {
    // storage blocked: reload anyway
  }
  location.reload();
}

/** Call once at startup. `busy()` defers the reload while a session runs. */
export function startUpdates(busy: () => boolean) {
  try {
    const updated = sessionStorage.getItem(NOTICE_KEY);
    if (updated) {
      sessionStorage.removeItem(NOTICE_KEY);
      toast(`Updated to ${updated}`);
    }
  } catch {
    // ignore
  }
  if (import.meta.env.DEV) return;

  let registration: ServiceWorkerRegistration | undefined;
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./sw.js").then((r) => (registration = r)).catch(() => undefined);
    navigator.serviceWorker.addEventListener("controllerchange", () => reloadInto("the latest version"));
  }

  const check = async () => {
    const latest = await latestVersion();
    if (!latest || latest === VERSION) return;
    if (busy()) {
      // A notarization is in flight; try again soon rather than kill it.
      setTimeout(check, 10_000);
      return;
    }
    toast(`New version ${latest}, updating…`);
    if (registration) {
      await registration.update().catch(() => undefined);
      const waiting = registration.waiting ?? registration.installing;
      if (waiting) {
        waiting.postMessage("skip-waiting");
        // controllerchange reloads; fall back if it never comes.
        setTimeout(() => reloadInto(latest), 5000);
        return;
      }
    }
    reloadInto(latest);
  };
  setInterval(check, CHECK_EVERY_MS);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") check();
  });
  check();
}

export { toast };
