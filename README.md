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

Requires Node 20.19+. No runtime dependencies. Screenshots additionally need
any installed Chromium-family browser.

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

### Serving to other machines

`--host 0.0.0.0` exposes the board on the LAN, which is how you would run it on
a NAS or dev box. Links are built from whatever host you opened the board on —
`nas.local`, a LAN IP, a tunnel hostname — never from the loopback address the
scanner probes, so clicking a row reaches the right machine. Services bound only
to `127.0.0.1` genuinely cannot be reached from elsewhere; those are tagged
`loopback only` when you are viewing remotely, instead of handing you a link
that times out.

Note that this publishes a full inventory of the machine's listening ports to
anyone who can reach that address, so keep it to networks you trust.

Run under `sudo` to also see other users' processes — unprivileged `lsof` only
reports your own, so root-owned servers are found by the sweep but arrive
without a PID or project name.

### Screenshots

Servers that answer **2xx with HTML** get a page thumbnail, shown inline in the
list and full-width in grid view (`GRID` in the header, or `?view=grid`).

Capture runs after each background scan, never before, so the board is usable
immediately. Images are re-taken only when the page changes or after 15
minutes, and orphaned ones are pruned.

Redirects are followed: a server whose `/` answers 301 or 302 is captured at
wherever the chain lands, which is the normal shape for a dev server sending
you to `/login` or `/dashboard`. Two cases are deliberately skipped — a chain
that ends on an error page, and one that leaves this machine. The second
matters because Chrome follows redirects itself, so without the check a
localhost port pointing at an external site would have us fetching and storing
a picture of a public website.

There is no Puppeteer dependency: `ports` drives an already-installed Chrome,
Chromium, Edge or Brave over the DevTools Protocol, reusing one browser process
for the whole batch. Detection checks the usual install paths and then `PATH`;
point `PORTS_CHROME` at a binary to override it, or pass `--no-screenshots` to
switch the feature off.

If thumbnails cannot work, the reason is printed at startup and served from
`/api/health` rather than leaving you with silent blanks:

```
  ports · http://127.0.0.1:7373/
  screenshots off: no Chrome/Chromium/Edge/Brave found — install one, or set PORTS_CHROME=/path/to/binary
```

**On a headless box or NAS**, install any Chromium build (`apt install chromium`
is enough). Running as root — normal on a NAS or in a container — is handled:
Chrome refuses to start as root with its sandbox on, so `--no-sandbox` is added
automatically, along with `--disable-dev-shm-usage` for the small `/dev/shm` in
most container images.

CDP is spoken over a WebSocket client bundled with the package rather than
Node's global one, which only exists from 22.4. Screenshots therefore work on
Node 20 as well, matching the engine range the package actually claims.

Chrome's own `--screenshot` flag is not used, because it waits for the network
to fall idle and a dev server holding an HMR socket never does.

### Curating what you see

Most of a real machine's listening ports are app IPC endpoints you will never
open. Hide them:

```bash
ports hide 6463 44450     # from the board and from ls
ports unhide 6463
ports hidden              # what is hidden, and where the file lives
```

In the board, hover a row and click **×**; hidden entries collect in a
*Hidden by you* drawer where **+** restores them.

Rules live in `~/.config/ports/curation.json`, which is pretty-printed and
meant to be edited by hand:

```json
{
  "version": 1,
  "hiddenPorts": [6463],
  "hiddenRanges": ["44000-44999"],
  "hiddenCommands": ["Discord", "figma"]
}
```

`hiddenCommands` matches case-insensitively against the process name and full
command line, which is the quickest way to silence an app that scatters
listeners across changing ports. Edits are picked up while the server runs, and
clicking hide never rewrites rules you added by hand.

Un-hiding only removes an exact-port rule. If a range or command rule still
covers that port the UI says so, rather than leaving a button that appears to
do nothing.

### Status filter

Most localhost endpoints returning 4xx/5xx are internal IPC helpers you would
never open, so the board hides them by default and shows a count you can click
to reveal. Toggle from the header; the choice is remembered per host.

A third chip appears when it matters: **loopback**. Services bound only to
`127.0.0.1` cannot be reached from another machine, so when you open the board
remotely they are filtered out by default and the count says why. Viewed on the
machine itself the chip stays hidden, since there almost everything is loopback
and filtering would empty the board. Override with `?local=1`.

## Running as a service

```bash
sudo ports service install --port 80 --host 0.0.0.0   # systemd, system-wide
ports service install --user                          # systemd, just for you
ports service status
ports service uninstall
ports service print                                   # see the unit, change nothing
```

On Linux this writes a systemd unit; on macOS a launchd agent. `ExecStart` is
resolved from the running process, so it stays correct whether ports was
installed globally, run through npx, or is a source checkout.

A system-wide unit runs as **root** on purpose: that is what allows binding a
privileged port and what lets `lsof` see every user's processes, which is the
point of a machine-wide dashboard. Use `--user` if you would rather it ran as
you and saw only your own listeners — note that a user unit stops at logout
unless you enable lingering, which the installer reminds you about.

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
