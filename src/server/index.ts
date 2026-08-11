import http from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { PortRecord, ScanProgress } from '../shared/types.ts';
import { scan } from '../scan/scanner.ts';
import { isSweepDue } from '../scan/scheduler.ts';
import { createCacheWriter, loadCache, type CacheState } from '../cache/store.ts';
import { readFavicon } from '../cache/favicons.ts';
import { pruneScreenshots, readScreenshot } from '../cache/screenshots.ts';
import { captureAll } from '../scan/capture.ts';
import { screenshotAvailability } from '../scan/browser.ts';
import { createHub } from './sse.ts';
import {
  hideReasonFor,
  loadCuration,
  saveCuration,
  withHidden,
  withoutHidden,
  type Curation,
} from '../config/curation.ts';

/** Identifies our own instance when probing a port that is already taken. */
export const HEALTH_SIGNATURE = 'ports-scanner';

const HEARTBEAT_MS = 25_000;
/** Gap between background rescans once the first pass has finished. */
const RESCAN_INTERVAL_MS = 10_000;

export interface ServerOptions {
  port: number;
  host: string;
  /** Capture page thumbnails with a headless browser. */
  screenshots?: boolean;
}

export interface RunningServer {
  port: number;
  url: string;
  /** Why thumbnails are unavailable here, if they are. */
  screenshotIssue?: string;
  close: () => Promise<void>;
}

function uiDir(): string {
  // Resolves the same whether running from src/ under strip-types or dist/.
  return path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'ui');
}

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
};

function json(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

export async function startServer(options: ServerOptions): Promise<RunningServer> {
  const hub = createHub();
  const cache: CacheState = await loadCache();
  let curation: Curation = await loadCuration();
  const writer = createCacheWriter(1000);

  /** The live index, keyed by port. Cache entries start out stale. */
  const index = new Map<number, PortRecord>();
  for (const record of cache.records) index.set(record.port, { ...record, stale: true });

  let lastFullSweep = cache.lastFullSweep;
  let progress: ScanProgress = {
    phase: 'idle',
    scanned: 0,
    total: 0,
    found: index.size,
    startedAt: Date.now(),
    done: true,
  };

  /**
   * Stamp the current curation onto a record on the way out.
   *
   * Applied at serve time rather than stored, so a curation change never has
   * to invalidate the scan cache.
   */
  const decorate = (record: PortRecord): PortRecord => {
    const reason = hideReasonFor(record, curation);
    if (!reason) return record.hidden ? { ...record, hidden: false, hiddenBy: undefined } : record;
    return { ...record, hidden: true, hiddenBy: reason };
  };

  const snapshotRecords = () =>
    [...index.values()].map(decorate).sort((a, b) => a.port - b.port);

  const persist = () => {
    writer.schedule({ ...cache, lastFullSweep, records: snapshotRecords() });
  };

  // --- Scanning loop -------------------------------------------------------

  let scanning = false;
  let stopped = false;

  const runScan = async (force = false): Promise<void> => {
    if (scanning || stopped) return;
    scanning = true;
    try {
      await refreshCuration();
      const deep = force || isSweepDue(lastFullSweep);
      const result = await scan({
        deep,
        force,
        fetchFavicons: true,
        selfPort: options.port,
        prior: index.values(),
        onProgress: (p) => {
          progress = p;
          hub.send({ type: 'scan', progress: p });
        },
        onRecords: (records) => {
          for (const record of records) index.set(record.port, record);
          hub.send({ type: 'upsert', records: records.map(decorate) });
        },
      });

      for (const record of result.records) index.set(record.port, record);
      if (result.sweptFully) lastFullSweep = Date.now();
      persist();
    } catch {
      // A failed pass should not stop the loop; the next one may succeed.
    } finally {
      scanning = false;
    }

    // Thumbnails run after the scan has published everything, never before:
    // driving a browser takes seconds per page and the board should already be
    // usable by then. Results stream in as each one lands.
    if (options.screenshots !== false && !stopped) {
      await captureThumbnails();
    }
  };

  /**
   * Re-read curation.json from disk.
   *
   * The file is documented as hand-editable, so the in-memory copy has to be
   * refreshed rather than trusted: without this, an edit made while the server
   * runs is both invisible *and* silently overwritten by the next hide click.
   */
  const refreshCuration = async (): Promise<void> => {
    curation = await loadCuration();
  };

  let screenshotIssue: string | undefined;
  let capturing = false;
  const captureThumbnails = async (): Promise<void> => {
    if (capturing || stopped) return;
    capturing = true;
    try {
      const captured = await captureAll(index.values(), {
        skipPort: options.port,
        onCaptured: (record) => {
          index.set(record.port, record);
          hub.send({ type: 'upsert', records: [decorate(record)] });
        },
        onProblem: (reason) => {
          screenshotIssue = reason;
        },
        // A success clears any earlier report, so the health endpoint reflects
        // the current state rather than the worst thing that ever happened.
        onWorking: () => {
          screenshotIssue = undefined;
        },
      });
      if (captured > 0) {
        persist();
        // Content-addressed images pile up as pages change; drop orphans.
        const live = new Set<string>();
        for (const record of index.values()) {
          if (record.screenshot) live.add(record.screenshot.hash);
        }
        await pruneScreenshots(live);
      }
    } catch {
      // No browser, or a capture failure. The board works fine without images.
    } finally {
      capturing = false;
    }
  };

  // --- Routes --------------------------------------------------------------

  const serveStatic = async (res: ServerResponse, file: string): Promise<void> => {
    const ext = path.extname(file);
    try {
      const body = await readFile(path.join(uiDir(), file));
      res.writeHead(200, {
        'content-type': MIME[ext] ?? 'application/octet-stream',
        'cache-control': 'no-cache',
      });
      res.end(body);
    } catch {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('Not found');
    }
  };

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const route = url.pathname;

    if (route === '/api/health') {
      return json(res, 200, {
        app: HEALTH_SIGNATURE,
        port: options.port,
        pid: process.pid,
        screenshots: options.screenshots === false
          ? { enabled: false, reason: 'disabled with --no-screenshots' }
          : { enabled: !screenshotIssue, ...(screenshotIssue ? { reason: screenshotIssue } : {}) },
      });
    }

    if (route === '/api/ports') {
      return json(res, 200, { records: snapshotRecords(), progress });
    }

    if (route === '/api/events') {
      hub.add(res);
      // Bring the new client fully up to date before any deltas arrive.
      res.write(
        `data: ${JSON.stringify({
          type: 'snapshot',
          records: snapshotRecords(),
          progress,
        })}\n\n`,
      );
      return;
    }

    if ((route === '/api/hide' || route === '/api/unhide') && req.method === 'POST') {
      const port = Number.parseInt(url.searchParams.get('port') ?? '', 10);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        return json(res, 400, { error: 'a valid ?port= is required' });
      }

      // Pick up any hand-edits before mutating, so writing one port back does
      // not clobber rules the user added since startup.
      await refreshCuration();
      curation =
        route === '/api/hide' ? withHidden(curation, port) : withoutHidden(curation, port);
      await saveCuration(curation);

      const record = index.get(port);
      if (record) hub.sendNow({ type: 'upsert', records: [decorate(record)] });

      return json(res, 200, {
        port,
        hidden: route === '/api/hide',
        // Say so when a broader rule still hides it, rather than reporting
        // success for a change the user will not see.
        stillHiddenBy: record ? hideReasonFor(record, curation) : undefined,
      });
    }

    if (route === '/api/curation') {
      await refreshCuration();
      return json(res, 200, curation);
    }

    if (route === '/api/rescan' && req.method === 'POST') {
      void runScan(true);
      return json(res, 202, { started: true });
    }

    if (route.startsWith('/api/favicon/')) {
      const hash = route.slice('/api/favicon/'.length);
      const icon = await readFavicon(hash);
      if (!icon) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, {
        'content-type': icon.contentType,
        // Content-addressed, so it can never go stale.
        'cache-control': 'public, max-age=31536000, immutable',
        'content-length': icon.bytes.length,
      });
      res.end(icon.bytes);
      return;
    }

    if (route.startsWith('/api/screenshot/')) {
      const hash = route.slice('/api/screenshot/'.length).replace(/\.jpg$/, '');
      const bytes = await readScreenshot(hash);
      if (!bytes) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, {
        'content-type': 'image/jpeg',
        'cache-control': 'public, max-age=31536000, immutable',
        'content-length': bytes.length,
      });
      res.end(bytes);
      return;
    }

    if (route === '/' || route === '/index.html') return serveStatic(res, 'index.html');
    if (route === '/app.js') return serveStatic(res, 'app.js');
    if (route === '/styles.css') return serveStatic(res, 'styles.css');

    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('Not found');
  };

  const server = http.createServer((req, res) => {
    void handle(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500, { 'content-type': 'text/plain' });
      res.end('Internal error');
    });
  });

  // SSE connections are long-lived by design.
  server.keepAliveTimeout = 0;
  server.headersTimeout = 0;
  server.requestTimeout = 0;

  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error) => reject(err);
    server.once('error', onError);
    server.listen(options.port, options.host, () => {
      server.removeListener('error', onError);
      resolve();
    });
  });

  const heartbeat = setInterval(() => hub.heartbeat(), HEARTBEAT_MS);
  heartbeat.unref();

  const rescan = setInterval(() => void runScan(false), RESCAN_INTERVAL_MS);
  rescan.unref();

  // Kick off the first pass immediately; clients already have cached data.
  void runScan(false);

  const availability =
    options.screenshots === false ? { ok: false } : await screenshotAvailability();
  if (!availability.ok && availability.reason) screenshotIssue = availability.reason;

  return {
    port: options.port,
    ...(options.screenshots !== false && availability.reason
      ? { screenshotIssue: availability.reason }
      : {}),
    url: `http://${options.host === '0.0.0.0' ? 'localhost' : options.host}:${options.port}/`,
    async close() {
      stopped = true;
      clearInterval(heartbeat);
      clearInterval(rescan);
      hub.closeAll();
      await writer.flush();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
