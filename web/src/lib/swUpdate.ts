/** Service-worker registration that actually delivers a new deploy.
 *
 * The generated SW precaches index.html and serves navigations from that cache,
 * so an open tab keeps rendering the previous build even after the new worker
 * installs. CloudFront invalidation cannot reach this layer at all — it is a
 * cache inside the browser. A feature shipped and verified live stayed invisible
 * to a returning visitor because of exactly this.
 *
 * `autoUpdate` + `skipWaiting` means the new worker takes control on its own; the
 * missing half is reloading the page once it does. `controllerchange` fires at
 * that moment, and the `reloaded` guard stops the refresh loop that occurs when
 * a worker claims clients repeatedly.
 */

let reloaded = false

export function registerServiceWorker(): void {
  if (!('serviceWorker' in navigator)) return

  // Sampled BEFORE registering. On a first-ever visit there is no controller,
  // and clientsClaim() then fires controllerchange for the initial takeover —
  // reloading there would bounce every new visitor for no reason. Only a
  // *replacement* of an existing controller means this tab is showing a stale
  // build.
  const hadController = navigator.serviceWorker.controller !== null

  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (!hadController || reloaded) return
    reloaded = true
    window.location.reload()
  })

  window.addEventListener('load', () => {
    void navigator.serviceWorker
      .register('/sw.js', { scope: '/' })
      .then((registration) => {
        // Long-lived tabs (a demo left open) would otherwise never check.
        setInterval(() => void registration.update(), 60 * 60 * 1000)
      })
      .catch(() => {
        // A failed SW registration must not take the app down with it: the app
        // works fine without offline support.
      })
  })
}
