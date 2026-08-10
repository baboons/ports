# ports

Find every HTTP/HTTPS server running on this machine, with titles, favicons and
the project each one belongs to.

```
$ ports ls

  80     http   502  502 Bad Gateway                        nginx          nginx
  3000   http   200  Acme Dashboard        acme-web (node)  Next.js
  5173   http   200  Vite + React          storefront       Vite
  18789  http   200  OpenClaw Control      openclaw-gateway

  4 non-HTTP listeners: 7265, 8021, 44438, 52259  (--all to show)

  8 web servers · 12 listeners · 5.9s
```

## Install

```bash
npx @baboons/ports             # zero-install, opens the live UI
npm i -g @baboons/ports        # then just: ports
```

Requires Node 20.19+. No runtime dependencies. (Screenshots additionally need
Node 22.4+ and any installed Chromium-family browser.)

## Usage

`ports` with no arguments serves a live web dashboard and opens it. Every HTTP
server is a real link — click, cmd-click, middle-click all work.

```
ports                  Serve the live web UI and open it
ports ls               Print a one-shot table instead

Server options
    --port <n>        Port to serve the UI on (default 7373)
    --host <h>        Interface to bind (default 127.0.0.1)
    --no-open         Do not open a browser
    --no-screenshots  Skip page thumbnails (no headless browser)

Listing options
-a, --all        Include listeners that do not speak HTTP
    --fast       Skip the full 1-65535 sweep (tiers 0-2 only)
-r, --refresh    Ignore cached descriptions and re-probe everything
    --no-cache   Do not read or write the cache at all
    --json       Emit JSON instead of a table
-q, --quiet      Suppress the progress line
```

The UI port resolves in this order: `--port`, then `PORTS_PORT`, then
`~/.config/ports/config.json`, then 7373. Naming a port explicitly makes a
collision a hard error naming the process that holds it; the default port
quietly moves aside instead. Ports below 1024 need root:

```bash
sudo npx @baboons/ports --port 80
```

If an instance is already running on the target port, a second invocation
detects it and just opens the browser rather than starting a rival scanner.

Run under `sudo` to also see other users' processes — unprivileged `lsof` only
reports your own, so root-owned servers are found by the sweep but arrive
without a PID or project name.

### Screenshots

Servers that answer **2xx with HTML** get a page thumbnail, shown inline in the
list and full-width in grid view (`GRID` in the header, or `?view=grid`).

Capture runs after each background scan, never before, so the board is usable
immediately. Images are re-taken only when the page changes or after 15
minutes, and orphaned ones are pruned.

There is no Puppeteer dependency: `ports` drives an already-installed Chrome,
Chromium, Edge or Brave over the DevTools Protocol, reusing one browser process
for the whole batch. Point `PORTS_CHROME` at a binary to override detection, or
pass `--no-screenshots` to switch the feature off. With no Chromium installed —
or on Node older than 22.4, which lacks a global `WebSocket` — everything else
works and thumbnails are simply absent.

Chrome's own `--screenshot` flag is not used, because it waits for the network
to fall idle and a dev server holding an HMR socket never does.

### Status filter

Most localhost endpoints returning 4xx/5xx are internal IPC helpers you would
never open, so the board hides them by default and shows a count you can click
to reveal. Toggle either bucket from the header; the choice is remembered.

## How it works

Discovery runs in tiers, fastest first, so results stream in rather than
arriving all at once:

| Tier | Method | Typical | Finds |
|---|---|---|---|
| 1 | `lsof` process table | ~50ms | Your listeners, **with PID and cwd** |
| 2 | Connect probe, ~80 common dev ports | ~200ms | Ports `lsof` cannot see |
| 3 | Connect sweep, 1–65535 | ~4–8s | Everything else |

Each port found is queued for HTTP probing immediately, so tier 1 and 2 results
are fully described while tier 3 is still sweeping.

**Protocol detection.** We send a plaintext `GET /` and read the first bytes
back. `HTTP/` means plaintext. A `0x15`/`0x16` TLS record, or a reset, means we
retry over TLS with certificate verification off — dev servers are usually
self-signed, and refusing them would defeat the point. Anything else is
recorded as a `tcp` listener and shown separately.

**Enrichment.** For anything that answers HTTP we capture status, `Server` and
framework fingerprints, `<title>`, `<meta name=description>`, OpenGraph tags,
theme colour and the best declared favicon (SVG preferred, then largest
raster). HTTPS ports also record certificate subject, issuer, expiry and
whether it is self-signed. PIDs resolve to a command, working directory and
project name read from `package.json` / `pyproject.toml` / `Cargo.toml` /
`go.mod`.

## Development

```bash
pnpm install
pnpm ls            # run from source, no build step
pnpm test          # unit tests for the parsers
pnpm typecheck
pnpm build         # compile to dist/
```

Source imports carry `.ts` extensions so `node --experimental-strip-types` can
run the tree directly; `tsc` rewrites them to `.js` when building `dist/`.

## Caching

State lives in `~/.cache/ports/` — `state.json` plus content-addressed
`favicons/` and `shots/` directories, written atomically so a crash mid-write
cannot corrupt it. Two things make repeat runs fast:

- **Per-port TTL.** A port whose description has not changed backs off
  exponentially, from 2s up to a 60s ceiling. Non-HTTP listeners sit at 120s,
  ports known to be down at 5 minutes.
- **Sweep TTL.** Tier 3 is the only expensive step, so its result is trusted
  for 5 minutes. Inside that window a run uses tiers 1 and 2 only.

Together those take a repeat `ports ls` from ~6s to ~0.1s. Ports discovered by
a sweep that is currently being skipped are still shown, marked stale rather
than dropped — caching makes the answer cheaper, never smaller.

The cache doubles as the index: servers that stop running are kept as history
rather than deleted, and appear under "Previously seen".

## Status

Complete: scanner core, cache and scheduler, SSE server, the live UI, and page
screenshots. Still to come:

5. **Index & search** — full-text search across titles, descriptions, commands
   and project names; grouping by project directory.
