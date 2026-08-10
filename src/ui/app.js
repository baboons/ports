// ports — live localhost board.
// Vanilla on purpose: no build step, no runtime deps, instant cold start.

const state = {
  /** port -> record */
  records: new Map(),
  /** Which status buckets are visible. 4xx/5xx start hidden. */
  show: { ok: true, err: false },
  /** 'list' is the dense board; 'grid' shows page thumbnails. */
  view: 'list',
  progress: null,
};

const el = {
  board: document.getElementById('board'),
  tcpBoard: document.getElementById('tcp-board'),
  historyBoard: document.getElementById('history-board'),
  tcpDrawer: document.getElementById('tcp-drawer'),
  historyDrawer: document.getElementById('history-drawer'),
  empty: document.getElementById('empty'),
  hiddenBar: document.getElementById('hidden-bar'),
  hiddenText: document.getElementById('hidden-text'),
  countOk: document.getElementById('count-ok'),
  countErr: document.getElementById('count-err'),
  countTcp: document.getElementById('count-tcp'),
  countDead: document.getElementById('count-dead'),
  lamp: document.getElementById('lamp'),
  phase: document.getElementById('phase'),
  scanbar: document.getElementById('scanbar'),
  scanfill: document.getElementById('scanfill'),
  conn: document.getElementById('conn'),
  subtitle: document.getElementById('subtitle'),
};

// --- Preferences -----------------------------------------------------------

const PREFS_KEY = 'ports.prefs.v1';

function loadPrefs() {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    if (!raw) return;
    const saved = JSON.parse(raw);
    if (saved && typeof saved.show === 'object') {
      state.show.ok = saved.show.ok !== false;
      state.show.err = saved.show.err === true;
    }
    if (saved && typeof saved.theme === 'string') {
      document.documentElement.dataset.theme = saved.theme;
    }
    if (saved && (saved.view === 'grid' || saved.view === 'list')) {
      state.view = saved.view;
    }
  } catch {
    // Corrupt prefs are not worth surfacing; defaults are fine.
  }
}

/**
 * Query parameters win over saved preferences, so a particular view can be
 * bookmarked or shared: ?view=grid&errors=1
 */
function applyQueryOverrides() {
  const params = new URLSearchParams(window.location.search);

  const view = params.get('view');
  if (view === 'grid' || view === 'list') state.view = view;

  const errors = params.get('errors');
  if (errors !== null) state.show.err = errors !== '0' && errors !== 'false';

  const ok = params.get('ok');
  if (ok !== null) state.show.ok = ok !== '0' && ok !== 'false';
}

function savePrefs() {
  try {
    localStorage.setItem(
      PREFS_KEY,
      JSON.stringify({
        show: state.show,
        view: state.view,
        theme: document.documentElement.dataset.theme,
      }),
    );
  } catch {
    // Private mode, quota, etc.
  }
}

// --- Classification --------------------------------------------------------

const isWeb = (r) => r.protocol === 'http' || r.protocol === 'https';

/** ok | warn | err | idle — drives both colour and the status filter. */
function bucket(record) {
  const status = record.http?.status;
  if (typeof status !== 'number' || status === 0) return 'idle';
  if (status >= 500) return 'err';
  if (status >= 400) return 'warn';
  return 'ok';
}

/** The filter the user actually toggles: healthy versus everything wrong. */
const isErrorBucket = (b) => b === 'warn' || b === 'err';

function passesFilter(record) {
  const b = bucket(record);
  return isErrorBucket(b) ? state.show.err : state.show.ok;
}

// --- Rendering -------------------------------------------------------------

/** Stable hue per port, so a server keeps its colour between runs. */
function hueFor(port) {
  return (port * 47) % 360;
}

function monogram(record) {
  const source =
    record.meta?.title || record.process?.projectName || record.process?.name || '';
  const letter = source.trim().charAt(0).toUpperCase();
  return /[A-Z0-9]/.test(letter) ? letter : '·';
}

function urlFor(record) {
  const host = record.probedAddress.includes(':')
    ? `[${record.probedAddress}]`
    : record.probedAddress;
  return `${record.protocol === 'https' ? 'https' : 'http'}://${host}:${record.port}/`;
}

function descriptionFor(record) {
  if (record.meta?.description) return record.meta.description;
  if (record.http?.redirectTo) return `→ ${record.http.redirectTo}`;
  if (record.error) return record.error;
  if (record.process?.cwd) return record.process.cwd.replace(/^\/Users\/[^/]+/, '~');
  return '';
}

function buildRow(record, view = 'list') {
  const web = isWeb(record);
  const node = document.createElement(web && record.alive ? 'a' : 'div');
  node.className = 'row';
  node.dataset.port = String(record.port);

  if (web && record.alive) {
    // Real anchors, so cmd-click and middle-click behave as expected.
    node.href = urlFor(record);
    node.target = '_blank';
    node.rel = 'noreferrer';
  }
  if (record.stale) node.classList.add('is-stale');

  // In grid view the thumbnail leads and the port overlays it; in list view
  // the port is the left-hand anchor you scan down.
  if (view === 'grid') {
    node.append(buildThumb(record));
    const badge = document.createElement('span');
    badge.className = 'card-port';
    badge.textContent = String(record.port);
    node.append(badge);
  }

  const body = view === 'grid' ? document.createElement('div') : node;
  if (view === 'grid') body.className = 'card-body';

  const port = document.createElement('div');
  port.className = 'port';
  port.textContent = String(record.port);
  body.append(port);

  // Favicon, or a deterministic monogram.
  const mark = document.createElement('div');
  mark.className = 'mark';
  if (record.meta?.faviconHash) {
    const img = document.createElement('img');
    img.src = `/api/favicon/${record.meta.faviconHash}`;
    img.alt = '';
    img.loading = 'lazy';
    // A cached icon can outlive the server that served it.
    img.onerror = () => {
      img.remove();
      mark.style.background = `hsl(${hueFor(record.port)} 45% 55%)`;
      const span = document.createElement('span');
      span.textContent = monogram(record);
      mark.append(span);
    };
    mark.append(img);
  } else {
    mark.style.background = `hsl(${hueFor(record.port)} 45% 55%)`;
    const span = document.createElement('span');
    span.textContent = monogram(record);
    mark.append(span);
  }
  body.append(mark);

  // Title, description and tags.
  const meta = document.createElement('div');
  meta.className = 'meta';

  const title = document.createElement('div');
  title.className = 'title';
  title.textContent =
    record.meta?.title ||
    record.process?.projectName ||
    record.process?.name ||
    (web ? 'untitled service' : 'non-HTTP listener');
  meta.append(title);

  const desc = descriptionFor(record);
  if (desc) {
    const d = document.createElement('div');
    d.className = 'desc';
    d.textContent = desc;
    meta.append(d);
  }

  const tags = document.createElement('div');
  tags.className = 'tags';
  const addTag = (text, cls) => {
    if (!text) return;
    const t = document.createElement('span');
    t.className = cls ? `tag ${cls}` : 'tag';
    t.textContent = text;
    tags.append(t);
  };
  addTag(record.process?.projectName, 'proj');
  addTag(record.http?.framework, 'fw');
  if (record.tls) addTag(record.tls.selfSigned ? 'self-signed' : 'TLS', 'tls');
  addTag(record.process?.name && !record.process?.projectName ? record.process.name : '');
  if (record.isSelf) addTag('this app', 'fw');
  if (tags.childElementCount > 0) meta.append(tags);

  body.append(meta);

  // Status readout.
  const right = document.createElement('div');
  right.className = 'right';

  // A small preview rides along in list view too. Thumbnails only living in
  // grid view meant the default screen never showed one.
  if (view === 'list' && record.screenshot) {
    const thumb = document.createElement('img');
    thumb.className = 'thumb';
    thumb.src = `/api/screenshot/${record.screenshot.hash}`;
    thumb.alt = '';
    thumb.loading = 'lazy';
    thumb.onerror = () => thumb.remove();
    right.append(thumb);
  }

  if (web) {
    const scheme = document.createElement('span');
    scheme.className = 'scheme';
    scheme.textContent = record.protocol.toUpperCase();
    right.append(scheme);
  }

  const b = bucket(record);
  const status = document.createElement('span');
  status.className = `status s-${b === 'warn' ? 'warn' : b}`;
  const dot = document.createElement('i');
  dot.className = `dot ${b}`;
  status.append(dot);
  const label = document.createElement('span');
  label.textContent = record.alive
    ? (record.http?.status ?? (web ? '—' : 'open'))
    : 'gone';
  status.append(label);
  right.append(status);

  if (web && record.alive) {
    const arrow = document.createElement('span');
    arrow.className = 'arrow';
    arrow.textContent = '↗';
    right.append(arrow);
  }

  body.append(right);
  if (view === 'grid') node.append(body);
  return node;
}

/** The page thumbnail, or a hatched placeholder showing the port. */
function buildThumb(record) {
  if (record.screenshot) {
    const img = document.createElement('img');
    img.className = 'shot';
    img.src = `/api/screenshot/${record.screenshot.hash}`;
    img.alt = `Screenshot of ${record.meta?.title ?? `port ${record.port}`}`;
    img.loading = 'lazy';
    img.width = record.screenshot.width;
    img.height = record.screenshot.height;
    // A pruned or missing blob falls back rather than showing a broken image.
    img.onerror = () => img.replaceWith(placeholderThumb(record));
    return img;
  }
  return placeholderThumb(record);
}

function placeholderThumb(record) {
  const div = document.createElement('div');
  div.className = 'shot-placeholder';
  div.textContent = String(record.port);
  return div;
}

let renderQueued = false;
function scheduleRender() {
  if (renderQueued) return;
  renderQueued = true;
  requestAnimationFrame(() => {
    renderQueued = false;
    render();
  });
}

function render() {
  const all = [...state.records.values()].sort((a, b) => a.port - b.port);

  const live = all.filter((r) => r.alive);
  const web = live.filter(isWeb);
  const tcp = live.filter((r) => !isWeb(r));
  const dead = all.filter((r) => !r.alive);

  const okCount = web.filter((r) => !isErrorBucket(bucket(r))).length;
  const errCount = web.filter((r) => isErrorBucket(bucket(r))).length;

  el.countOk.textContent = String(okCount);
  el.countErr.textContent = String(errCount);
  el.countTcp.textContent = String(tcp.length);
  el.countDead.textContent = String(dead.length);

  const visible = web.filter(passesFilter);
  // Only the main board switches to cards; the drawers stay compact lists.
  el.board.classList.toggle('as-grid', state.view === 'grid');
  paint(el.board, visible, state.view);
  el.empty.hidden = visible.length > 0;

  // Most localhost 4xx/5xx endpoints are internal IPC helpers rather than
  // things you would open, so they are hidden by default — but a board that
  // quietly drops most of the machine looks broken. Always say what is hidden.
  const hidden = web.length - visible.length;
  el.hiddenBar.hidden = hidden === 0;
  if (hidden > 0) {
    el.hiddenText.textContent = `${hidden} server${hidden === 1 ? '' : 's'} hidden — returning 4xx or 5xx`;
  }

  paint(el.tcpBoard, tcp);
  el.tcpDrawer.hidden = tcp.length === 0;

  paint(el.historyBoard, dead);
  el.historyDrawer.hidden = dead.length === 0;

  el.subtitle.textContent =
    web.length === 0
      ? 'localhost departure board'
      : `${web.length} web server${web.length === 1 ? '' : 's'} · ${live.length} listener${live.length === 1 ? '' : 's'}`;
}

/**
 * Reconcile a list into a container, reusing nodes by port so unrelated rows
 * do not lose focus or replay their entry animation on every update.
 */
function paint(container, records, view = 'list') {
  const existing = new Map();
  for (const child of container.children) existing.set(child.dataset.port, child);

  const wanted = new Set(records.map((r) => String(r.port)));
  for (const [port, node] of existing) {
    if (!wanted.has(port)) node.remove();
  }

  records.forEach((record, i) => {
    const key = String(record.port);
    const fresh = buildRow(record, view);
    const prev = existing.get(key);

    if (prev) {
      // Only touch the DOM when something actually changed.
      if (prev.innerHTML !== fresh.innerHTML || prev.tagName !== fresh.tagName) {
        if (prev.tagName === fresh.tagName) {
          prev.innerHTML = fresh.innerHTML;
          prev.className = fresh.className;
          if (fresh.href) prev.href = fresh.href;
          flash(prev);
        } else {
          prev.replaceWith(fresh);
          flash(fresh);
        }
      }
    } else {
      fresh.style.animationDelay = `${Math.min(i * 22, 400)}ms`;
      container.append(fresh);
    }
  });

  // Keep DOM order matching sort order.
  records.forEach((record) => {
    const node = container.querySelector(`[data-port="${record.port}"]`);
    if (node) container.append(node);
  });
}

function flash(node) {
  node.classList.remove('flash');
  void node.offsetWidth;
  node.classList.add('flash');
}

// --- Progress --------------------------------------------------------------

const PHASE_LABEL = {
  idle: '',
  cache: 'reading cache',
  lsof: 'reading process table',
  common: 'checking common ports',
  sweep: 'sweeping all ports',
  probing: 'probing services',
  done: '',
};

function applyProgress(progress) {
  state.progress = progress;
  const active = progress && !progress.done && progress.phase !== 'idle';

  el.lamp.dataset.state = active ? 'scanning' : 'live';
  el.scanbar.dataset.idle = active ? 'false' : 'true';

  if (!active) {
    el.phase.textContent = '';
    el.scanfill.style.width = '0%';
    return;
  }

  const pct = progress.total > 0 ? (progress.scanned / progress.total) * 100 : 8;
  el.scanfill.style.width = `${Math.max(pct, 4)}%`;

  const label = PHASE_LABEL[progress.phase] ?? progress.phase;
  el.phase.textContent =
    progress.total > 0
      ? `${label} — ${progress.scanned.toLocaleString()} / ${progress.total.toLocaleString()}`
      : label;
}

// --- Transport -------------------------------------------------------------

function apply(records) {
  for (const record of records) state.records.set(record.port, record);
}

function connect() {
  const source = new EventSource('/api/events');

  source.onopen = () => {
    el.conn.textContent = 'live';
    el.conn.dataset.state = 'open';
  };

  source.onmessage = (event) => {
    let payload;
    try {
      payload = JSON.parse(event.data);
    } catch {
      return;
    }

    switch (payload.type) {
      case 'snapshot':
        state.records.clear();
        apply(payload.records);
        applyProgress(payload.progress);
        break;
      case 'upsert':
        apply(payload.records);
        break;
      case 'remove':
        for (const id of payload.ids) state.records.delete(Number(id));
        break;
      case 'scan':
        applyProgress(payload.progress);
        return scheduleRender();
      default:
        return;
    }
    scheduleRender();
  };

  source.onerror = () => {
    el.conn.textContent = 'reconnecting…';
    el.conn.dataset.state = 'down';
    el.lamp.dataset.state = 'idle';
    // EventSource retries on its own using the server's retry hint.
  };
}

// --- Controls --------------------------------------------------------------

for (const button of document.querySelectorAll('.seg button[data-filter]')) {
  button.addEventListener('click', () => {
    const key = button.dataset.filter;
    state.show[key] = !state.show[key];
    button.classList.toggle('on', state.show[key]);
    button.setAttribute('aria-pressed', String(state.show[key]));
    savePrefs();
    render();
  });
}

// View is a choice between two, not a pair of independent toggles.
for (const button of document.querySelectorAll('.seg button[data-view]')) {
  button.addEventListener('click', () => {
    state.view = button.dataset.view;
    syncViewButtons();
    savePrefs();
    // Cards and rows are different DOM; rebuild rather than reconcile.
    el.board.replaceChildren();
    render();
  });
}

function syncViewButtons() {
  for (const button of document.querySelectorAll('.seg button[data-view]')) {
    const on = button.dataset.view === state.view;
    button.classList.toggle('on', on);
    button.setAttribute('aria-pressed', String(on));
  }
}

/** Reveal the filtered-out servers, keeping the toggle in sync. */
el.hiddenBar.addEventListener('click', () => {
  state.show.err = true;
  const button = document.querySelector('.seg button[data-filter="err"]');
  button.classList.add('on');
  button.setAttribute('aria-pressed', 'true');
  savePrefs();
  render();
});

document.getElementById('rescan').addEventListener('click', () => {
  fetch('/api/rescan', { method: 'POST' }).catch(() => {});
});

document.getElementById('theme').addEventListener('click', () => {
  const root = document.documentElement;
  const dark =
    root.dataset.theme === 'dark' ||
    (root.dataset.theme === 'auto' &&
      window.matchMedia('(prefers-color-scheme: dark)').matches);
  root.dataset.theme = dark ? 'light' : 'dark';
  savePrefs();
});

// --- Boot ------------------------------------------------------------------

loadPrefs();
applyQueryOverrides();
for (const button of document.querySelectorAll('.seg button[data-filter]')) {
  const on = state.show[button.dataset.filter];
  button.classList.toggle('on', on);
  button.setAttribute('aria-pressed', String(on));
}
syncViewButtons();
connect();
