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
import { createHub } from './sse.ts';

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

  const snapshotRecords = () =>
    [...index.values()].sort((a, b) => a.port - b.port);

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
          hub.send({ type: 'upsert', records });
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

  let capturing = false;
  const captureThumbnails = async (): Promise<void> => {
    if (capturing || stopped) return;
    capturing = true;
    try {
      const captured = await captureAll(index.values(), {
        skipPort: options.port,
        onCaptured: (record) => {
          index.set(record.port, record);
          hub.send({ type: 'upsert', records: [record] });
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
      return json(res, 200, { app: HEALTH_SIGNATURE, port: options.port, pid: process.pid });
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

  return {
    port: options.port,
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
