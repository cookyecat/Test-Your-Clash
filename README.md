# Network Observatory / 网络状态台

A single-file, local-first Clash/Mihomo network observatory. The website connects directly to the user's controller; no credentials, subscriptions, or results are uploaded to a service.

## Develop and build

Requires Node.js 22+ and Python 3.9+ for the optional Mac helper.

```sh
npm ci
npm test
npm run build
npm run preview
```

The deployable website is `.internal/dist/index.html`; `CNAME` is copied alongside it. Source modules are intentionally tracked instead of the generated HTML. Open the preview at http://127.0.0.1:4173. Build and test output must remain under `.internal/`.

## Connect

Enter your controller URL (default `http://127.0.0.1:9090`) and optional Secret. Allow the exact website origin in Mihomo CORS settings and approve your browser's local-network permission. Connection failures may be indistinguishable from CORS and permission denials. An alternative is to serve the built HTML using Mihomo `external-ui`.

Direct-controller monitoring runs in the foreground page. Hidden pages pause, reloads interrupt sessions, and errors/gaps do not count as failed probes. HTTPS uses the per-node delay endpoint without changing proxy selections. A short successful test does not establish long-term availability. P50/P95 cover retained successful samples; cumulative counts cover the session. Browser history keeps up to 120 sessions/30 days and 100,000 samples/24 hours per session.

## Mac helper

```sh
npm run build
python3 scripts/package-helper.py
```

This produces `.internal/Network-Status-Helper-macOS.zip`. Installation requires macOS and Python 3.9+. The installer performs local ad-hoc signing; it is not Developer ID notarized. The existing `netstatus://` pairing protocol and origin-bound authorization remain supported. Helper-owned jobs keep running after the page closes. A helper can be run from source with `NETDASH_HTML` pointing to the built HTML. `NETDASH_CONTROLLER` and `NETDASH_SECRET` optionally select an HTTP(S) controller instead of the existing Clash Verge socket discovery. Do not put secrets into tracked files or command history.

System DNS evidence still comes from macOS and the Clash Verge generated configuration where available; it does not prove the resolver used by each packet. Other desktop systems use controller mode in this release.

## Validation

`npm test` covers metric denominators, missing evidence, error classification, cyclic groups, scheduling and CSV safety. `node tests/mock-controller.mjs` starts an isolated fixture on port 19090, with two successful nodes and one timeout node; it never contacts real proxies. Connect the preview to that address for repeatable manual UI checks. Test screenshots and reports belong in `.internal/`.

## Deployment

The Pages workflow builds and tests the single HTML, packages the helper as a workflow artifact, and deploys `.internal/dist` when changes reach `main`. Set repository Pages source to **GitHub Actions** when migrating from branch publishing. The `CNAME` remains `clash.starverse.chat`.

Tag a release `v5.x.x` to publish the helper installer through the release workflow. The app links to the repository's latest release. Release binaries and Pages output are generated from source and are never committed.

Old `network-dashboard/v1` snapshots can be imported as read-only topology evidence. The helper's existing database remains in place. V5 browser observations use a separate IndexedDB database and can be exported as JSON/CSV.

## DNS topology and bulk selection

The Network map begins with a clickable DNS configuration graph: system resolvers, Clash DNS, domain policies, default/fallback upstreams, proxy/direct hostname resolvers, and bootstrap resolution. Solid facts come from the helper/snapshot; unobserved paths remain unknown. DNS upstream branches are alternatives by purpose, never displayed as sequential network hops. Importing a snapshot disconnects the live view so historical data cannot be mistaken for live controller state.

For hundreds of nodes, choose a group (or All nodes) and click **Select all matches (N)**. Selection includes offscreen rows, honors both search and issue filters, and accumulates across groups with duplicate nodes removed. **Select entire scope**, **Invert matches**, and the table-header checkbox share these rules. Sessions are limited to 500 nodes; larger selections are rejected without silently truncating. Use **Select first 500** explicitly when needed. Probe concurrency stays bounded, and UI/storage updates are coalesced for large batches.

Run `node tests/mock-controller.mjs --large` for a synthetic 300-node controller. `tests/fixtures/dns-snapshot.json` is a small synthetic DNS fixture for the import UI. Neither fixture contains user configuration or contacts real DNS/proxy servers.
