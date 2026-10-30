// Service worker: offline shell, versioned cache. The version is stamped in
// at build time; a new deploy means a new cache and a new worker.
const VERSION = "__APP_VERSION__";
const CACHE = `tlsnc-${VERSION}`;

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(["./", "./index.html", "./manifest.webmanifest", "./icon.svg"])));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()),
  );
});

self.addEventListener("message", (event) => {
  if (event.data === "skip-waiting") self.skipWaiting();
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.origin !== location.origin) return;
  // Never cache the API or the version probe.
  if (url.pathname.startsWith("/v1/") || url.pathname === "/info" || url.pathname.startsWith("/.well-known/") || url.pathname.endsWith("/version.json")) return;
  // Hashed build assets and the prover package of this version never
  // change within one cache: cache first.
  if (url.pathname.includes("/assets/") || url.pathname.includes("/tlsnc-wasm/")) {
    event.respondWith(
      caches.match(event.request).then(
        (hit) =>
          hit ??
          fetch(event.request).then((resp) => {
            if (resp.ok) caches.open(CACHE).then((c) => c.put(event.request, resp.clone()));
            return resp;
          }),
      ),
    );
    return;
  }
  // The page itself: network first, so a deploy shows up immediately.
  event.respondWith(
    fetch(event.request)
      .then((resp) => {
        if (resp.ok) caches.open(CACHE).then((c) => c.put(event.request, resp.clone()));
        return resp;
      })
      .catch(() => caches.match(event.request).then((hit) => hit ?? caches.match("./index.html"))),
  );
});
