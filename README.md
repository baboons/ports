# ports

Find every HTTP server running on this machine, and give them names.

```
$ ports

  80     http   200  Acme Dashboard        acme-web (node)  Next.js
  4000   http   200  Acme API              acme-api         Express
  5173   http   200  Vite + React          storefront       Vite
  18789  http   200  OpenClaw Control      openclaw-gateway

  4 non-HTTP listeners: 7265, 8021, 44438, 52259  (--all to show)

  4 web servers · 8 listeners · 1.6s
```

```
$ ports adopt

  acme  ·  turborepo  ·  5 workspaces

  workspace     port  source     domain
  apps/api      4000  running    api.localhost
  apps/docs     5174  running    docs.localhost
  apps/web      3000  running    web.localhost
  packages/ui      —  no server  skipped

  bind 3? [Y/n]
```

Then `http://web.localhost` reaches `localhost:3000`.

## Install

```bash
cargo install ports          # from source
brew install baboons/tap/ports
npx @baboons/ports           # fetches a prebuilt binary
```

No runtime dependencies. Nothing needs root unless you want port 80.

## Listing

`ports` with no arguments prints what is running.

```
-a, --all       Include listeners that do not speak HTTP
    --fast      Skip the full 1-65535 sweep
-r, --refresh   Ignore cached descriptions and re-probe everything
    --no-cache  Do not read or write the cache at all
    --json      Emit JSON instead of a table
-q, --quiet     Suppress the progress line
```

Discovery runs in tiers, fastest first:

| Tier | Method | Typical | Finds |
|---|---|---|---|
| 1 | Kernel socket table | ~5ms | Your listeners, **with pid and cwd** |
| 2 | Connect probe, ~90 common dev ports | ~150ms | Ports the socket table cannot see |
| 3 | Connect sweep, 1–65535 | ~1.5s | Everything else |

Run under `sudo` to also see other users' processes — unprivileged socket
enumeration only reports your own, so root-owned servers are found by the sweep
but arrive without a pid or project name.

**Protocol detection.** We send a plaintext `GET /` and read the first bytes
back. `HTTP/` means plaintext. A `0x15`/`0x16` TLS record, or a reset, means we
retry over TLS with verification off — dev servers are usually self-signed, and
refusing them would defeat the point.

**Caching.** State lives in `~/.cache/ports/`, written atomically. A port whose
description has not changed backs off exponentially from 2s to a 60s ceiling;
the full sweep is trusted for five minutes. Together those take a repeat run
from ~1.6s to ~0.03s. Ports discovered by a sweep that is currently being
skipped are still shown, marked stale rather than dropped — caching makes the
answer cheaper, never smaller.

### Curating what you see

Most of a machine's listening ports are app IPC endpoints you will never open:

```bash
ports hide 6463 44450
ports unhide 6463
ports hidden              # what is hidden, and where the file lives
```

Rules live in `~/.config/ports/curation.json`, pretty-printed and meant to be
edited by hand. `hiddenCommands` matches case-insensitively against the process
name and command line, which is the quickest way to silence an app that
scatters listeners across changing ports.

## Local domains

```bash
ports bind myapp 4000      # myapp.localhost → 127.0.0.1:4000
ports bind 4000            # name inferred from the project running there
ports bind api.myapp 4001  # multi-level names work
ports unbind myapp
ports links                # what is bound, and whether it is up
```

Bindings live in `~/.config/ports/bindings.json`. The proxy watches that file,
so a new binding is live within half a second — no restart.

### `ports adopt`

Run it in a repo and every server in it gets a name. It finds ports two ways:

- **Observed** — a running server whose process cwd is inside a workspace. This
  is the reliable one: it watches rather than guesses.
- **Declared**, for whatever is not up yet — `PORT` in `.env`, a `--port` flag
  in the dev script, `server.port` in a vite or astro config, and only then the
  framework's documented default.

A workspace with no evidence of a server is listed as skipped rather than given
an invented port. Re-running updates moved ports in place rather than piling up
duplicates.

Workspaces come from the package manager's own manifest — `pnpm-workspace.yaml`,
`package.json` workspaces, Cargo `members`, `go.work` — so turborepo, Nx and
Lerna all work by way of whatever they delegate to. Adopting from inside
`apps/web` still finds its siblings.

```
ports adopt [path]    Bind every server in a project
    --dry-run         Show what would happen, write nothing
-y, --yes             Skip the confirmation
    --prefix          Qualify every name with the repo: web.acme.localhost
```

### Running the proxy

```bash
ports serve                       # foreground, Ctrl-C to stop
ports service install             # launchd or systemd, starts at boot
ports service status
ports service uninstall
ports service print               # see the unit, change nothing
```

Ports 80 and 443 are the default and are the only reason any of this needs
privileges. Set both above 1024 and nothing ever does:

```jsonc
// ~/.config/ports/bindings.json
{ "httpPort": 8080, "httpsPort": 8443 }
```

`ports service install` picks the right variant on its own. On Linux a system
unit binds `:80` via `AmbientCapabilities=CAP_NET_BIND_SERVICE` and **is never
root**. macOS has no equivalent, so a LaunchDaemon starts as root, binds, and
then permanently drops to your uid before serving a single request.

### Choosing a domain

`.localhost` is the default because it costs nothing: macOS, systemd-resolved
and every browser already send `*.localhost` to loopback with no configuration,
no DNS server and no sudo. It is also a *trustworthy origin*, so service
workers, `crypto.subtle`, WebAuthn and `Secure` cookies work over plain HTTP.

```bash
ports domain              # show the current one
ports domain test         # switch
sudo ports domain test --install
```

Any other TLD needs one resolver entry, which `--install` writes: on macOS
`/etc/resolver/<tld>` pointing at our DNS responder on `127.0.0.1:15353`
(`/etc/resolver` supports a `port` keyword, so the responder stays
unprivileged); on Linux a systemd-resolved drop-in, or a managed block in
`/etc/hosts`.

`.dev`, `.app`, `.zip` and `.mov` are refused: they are real TLDs on the HSTS
preload list, so browsers force HTTPS before the request reaches anything and
plain HTTP could never work. `.local` is refused because mDNS owns it. `.test`
is reserved by RFC 6761 for exactly this and is the best custom choice.

### HTTPS

```bash
ports ca                 # which CA certificates come from
ports ca install         # generate one, if you have no mkcert root
```

Leaf certificates are minted per hostname on demand and cached under
`~/.local/share/ports/certs/`. They are signed by a local CA — mkcert's if you
have one, which most people already do and which the machine already trusts, so
nothing new joins your trust store.

HTTPS stays off unless a CA is available. A plain self-signed certificate is
worse than no HTTPS: the browser interstitial is clickable, but `fetch()` to
that origin is not, so it fails opaquely in exactly the case you would hit
first.

If you are on `.localhost` you may not need any of this — plain HTTP already
gets the secure-context APIs there.

### When something is wrong

```bash
ports doctor
```

```
  ✓ resolution    *.localhost resolves to loopback
  – dns           *.localhost needs no DNS server
  ✓ proxy         proxy answering on port 80
  ! upstreams     1 of 3 upstreams down: api.localhost
  ✓ certificates  issuing from the mkcert root
  ✓ end to end    web.localhost reaches its server
```

A local domain can fail at five layers and the browser reports nearly all of
them identically, so each is checked separately.

## What changes when you use a name

`myapp.localhost` and `localhost:3000` are **different origins**. Most of what
follows is a one-time fix, but none of it is a bug in the proxy.

**Dev servers will block you first.** This is DNS-rebinding protection working
as intended. `ports bind` detects the rejection and prints the fix:

| Stack | Fix |
|---|---|
| Vite | `server: { allowedHosts: ['.localhost'] }` |
| webpack-dev-server | `devServer: { allowedHosts: 'all' }` |
| Rails | `config.hosts << '.localhost'` |
| Django | `ALLOWED_HOSTS = ['.localhost']` |
| Next.js Server Actions | `experimental.serverActions.allowedOrigins` |

**Browser state does not carry over.** Cookies, `localStorage` and IndexedDB are
per-origin, so you will be logged out the first time and the app starts empty.
You cannot share cookies across `.localhost` subdomains with a `Domain=`
attribute; `.test` is more permissive there if `app.test` and `api.test` need a
shared session.

**CORS and OAuth need the new origin registered.** A backend hardcoding
`Access-Control-Allow-Origin: http://localhost:3000` will reject you, and a
redirect URI registered as `http://localhost:3000/callback` will not match.
Some providers — Google notably — refuse plain-HTTP redirect URIs for anything
but literal `localhost`, which may force you onto HTTPS.

**HSTS is sticky.** If any app ever sends `Strict-Transport-Security` on your
local hostname, the browser pins HTTPS for that name and you cannot go back to
HTTP without clearing it in `chrome://net-internals/#hsts`. `ports` does not
strip the header, so avoid sending it in development.

What the proxy does handle: WebSocket upgrades (without which Vite's HMR socket
never connects and the page silently stops hot-reloading), the original `Host`
preserved plus `X-Forwarded-*` so frameworks generate correct absolute URLs,
unbuffered streaming so SSE works, and redirects that name the upstream
directly rewritten back to the bound hostname.

## Development

```bash
cargo test
cargo build --release
cargo run -- adopt --dry-run
```

The crate is a library plus a binary, so the proxy can be driven end-to-end
from `tests/` — a WebSocket upgrade tunnelling bytes both ways, and an SSE
stream asserted to arrive unbuffered. Those are the two things a naive proxy
breaks without any error surfacing.

## License

MIT
