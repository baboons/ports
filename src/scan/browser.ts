import { spawn, type ChildProcess } from 'node:child_process';
import { access, mkdtemp, rm } from 'node:fs/promises';
import { constants } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CdpSocket } from './ws.ts';

/**
 * A very small Chrome DevTools Protocol client, used only to take screenshots.
 *
 * Chrome's built-in `--screenshot` flag is not usable here: it waits for the
 * page to go quiet, and a dev server with an HMR websocket or an SSE stream
 * never does, so it hangs until killed. Driving CDP lets us shoot on a timer
 * instead, and reuse one browser process across every capture rather than
 * paying a ~4s cold start each time.
 *
 * The WebSocket client is our own (see ws.ts) rather than Node's global, which
 * only exists from 22.4: this package supports Node 20, and a NAS or Debian box
 * is exactly where the older runtime turns up.
 */

const CANDIDATES_DARWIN = [
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
  '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
  '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary',
];

const CANDIDATES_LINUX = [
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/snap/bin/chromium',
  '/usr/lib/chromium/chromium',
  '/usr/lib/chromium-browser/chromium-browser',
  '/var/lib/flatpak/exports/bin/org.chromium.Chromium',
  '/usr/bin/microsoft-edge',
  '/usr/bin/brave-browser',
  '/opt/google/chrome/chrome',
];

/**
 * Binary names to look for on PATH.
 *
 * NAS and container images put browsers in places no fixed list predicts, so
 * the absolute candidates above are only the fast path.
 */
const PATH_NAMES = [
  'google-chrome',
  'google-chrome-stable',
  'chromium',
  'chromium-browser',
  'brave-browser',
  'microsoft-edge',
];

const CANDIDATES_WIN = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
];

async function exists(file: string): Promise<boolean> {
  try {
    await access(file, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** Locate a Chromium-family browser, or undefined if the host has none. */
export async function findBrowser(): Promise<string | undefined> {
  const override = process.env['PORTS_CHROME'];
  if (override && (await exists(override))) return override;

  const list =
    process.platform === 'darwin'
      ? CANDIDATES_DARWIN
      : process.platform === 'win32'
        ? CANDIDATES_WIN
        : CANDIDATES_LINUX;

  for (const candidate of list) {
    if (await exists(candidate)) return candidate;
  }

  // Fall back to PATH, which is how most non-standard installs are reachable.
  if (process.platform !== 'win32') {
    const dirs = (process.env['PATH'] ?? '').split(path.delimiter).filter(Boolean);
    for (const dir of dirs) {
      for (const name of PATH_NAMES) {
        const candidate = path.join(dir, name);
        if (await exists(candidate)) return candidate;
      }
    }
  }

  return undefined;
}

export interface ScreenshotAvailability {
  ok: boolean;
  reason?: string;
  executable?: string;
}

/**
 * Why screenshots will or will not work here.
 *
 * The capture path degrades silently by design, which is right for a feature
 * nobody asked for - but it leaves someone on a headless box with no way to
 * tell whether it is broken or simply unavailable. This spells it out.
 */
export async function screenshotAvailability(): Promise<ScreenshotAvailability> {
  const executable = await findBrowser();
  if (!executable) {
    return {
      ok: false,
      reason:
        'no Chrome/Chromium/Edge/Brave found — install one, or set PORTS_CHROME=/path/to/binary',
    };
  }

  return { ok: true, executable };
}

interface Pending {
  resolve: (value: unknown) => void;
  reject: (reason: Error) => void;
}

export interface CaptureOptions {
  /** CSS pixels of the emulated viewport - the layout the page sees. */
  width?: number;
  height?: number;
  /**
   * Output pixels per CSS pixel. Below 1 this shrinks the image, which is what
   * we want for thumbnails: the page still lays out at desktop width, but the
   * file is a quarter of the size.
   */
  scale?: number;
  /** How long to let the page paint before shooting. */
  settleMs?: number;
  /** Hard ceiling for one capture, including navigation. */
  timeoutMs?: number;
}

export interface Capture {
  bytes: Buffer;
  contentType: string;
}

export class Screenshotter {
  #proc: ChildProcess | undefined;
  #ws: CdpSocket | undefined;
  #profileDir: string | undefined;
  #nextId = 1;
  #pending = new Map<number, Pending>();
  #starting: Promise<void> | undefined;
  #executable: string;
  /** Why the most recent capture failed, for diagnostics. */
  lastError: string | undefined;
  /**
   * True when the browser itself would not start.
   *
   * Distinct from a page that failed to render: a startup failure affects
   * every capture equally and is worth reporting and giving up on, whereas one
   * slow page says nothing about the next.
   */
  startupFailed = false;

  constructor(executable: string) {
    this.#executable = executable;
  }

  static async create(): Promise<Screenshotter | undefined> {
    const executable = await findBrowser();
    return executable ? new Screenshotter(executable) : undefined;
  }

  async #start(): Promise<void> {
    if (this.#ws?.connected) return;
    if (this.#starting) return this.#starting;

    this.#starting = (async () => {
      // A throwaway profile keeps us out of the user's real Chrome session.
      this.#profileDir = await mkdtemp(path.join(os.tmpdir(), 'ports-shots-'));

      const args = [
        '--headless=new',
        '--remote-debugging-port=0',
        `--user-data-dir=${this.#profileDir}`,
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-gpu',
        '--hide-scrollbars',
        '--mute-audio',
        '--disable-extensions',
        '--disable-background-networking',
        '--disable-sync',
        // Dev servers overwhelmingly use self-signed certificates.
        '--ignore-certificate-errors',
        '--allow-insecure-localhost',
      ];

      if (process.platform === 'linux') {
        // Containers and NAS images ship a tiny /dev/shm, which Chrome will
        // exhaust and crash on mid-render.
        args.push('--disable-dev-shm-usage');

        // Chrome flatly refuses to start as root with its sandbox enabled, and
        // running as root is the norm on a NAS or in a container. The sandbox
        // guards against hostile page content; here the pages are servers on
        // this same machine, already reachable by the user we are running as.
        if (typeof process.getuid === 'function' && process.getuid() === 0) {
          args.push('--no-sandbox', '--disable-setuid-sandbox');
        }
      }

      const proc = spawn(this.#executable, args, { stdio: ['ignore', 'ignore', 'pipe'] });
      this.#proc = proc;

      // Chrome prints the devtools URL to stderr once it is listening.
      const endpoint = await new Promise<string>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('browser did not start')), 15_000);
        let buffer = '';

        proc.stderr?.on('data', (chunk: Buffer) => {
          buffer += chunk.toString('utf8');
          const match = /ws:\/\/[^\s]+/.exec(buffer);
          if (match) {
            clearTimeout(timer);
            resolve(match[0]);
          }
        });
        proc.once('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });
        proc.once('exit', (code) => {
          clearTimeout(timer);
          // Chrome explains itself on stderr ("Running as root without
          // --no-sandbox is not supported", missing shared libraries, ...).
          // Passing that through is the difference between a fixable report
          // and a shrug.
          const detail = buffer.trim().split('\n').filter(Boolean).slice(-2).join(' / ');
          reject(
            new Error(
              `browser exited during startup (code ${code})${detail ? `: ${detail}` : ''}`,
            ),
          );
        });
      });

      const ws = new CdpSocket();
      ws.on({
        onMessage: (data) => {
          let msg: { id?: number; result?: unknown; error?: { message?: string } };
          try {
            msg = JSON.parse(data);
          } catch {
            return;
          }
          if (typeof msg.id !== 'number') return;
          const pending = this.#pending.get(msg.id);
          if (!pending) return;
          this.#pending.delete(msg.id);
          if (msg.error) pending.reject(new Error(msg.error.message ?? 'cdp error'));
          else pending.resolve(msg.result);
        },
        onClose: () => {
          for (const pending of this.#pending.values()) {
            pending.reject(new Error('devtools disconnected'));
          }
          this.#pending.clear();
          this.#ws = undefined;
        },
      });

      await ws.connect(endpoint);
      this.#ws = ws;
    })();

    try {
      await this.#starting;
    } finally {
      this.#starting = undefined;
    }
  }

  #send(method: string, params: Record<string, unknown> = {}, sessionId?: string): Promise<unknown> {
    const ws = this.#ws;
    if (!ws?.connected) {
      return Promise.reject(new Error('devtools not connected'));
    }
    const id = this.#nextId++;
    const payload: Record<string, unknown> = { id, method, params };
    if (sessionId) payload['sessionId'] = sessionId;

    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      const timer = setTimeout(() => {
        if (this.#pending.delete(id)) reject(new Error(`${method} timed out`));
      }, 20_000);
      timer.unref?.();
      try {
        ws.send(JSON.stringify(payload));
      } catch (err) {
        this.#pending.delete(id);
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  /**
   * Load a URL in a throwaway tab and return a PNG.
   *
   * Deliberately shoots after a fixed settle delay rather than waiting for the
   * network to fall idle, because the pages we care about frequently hold a
   * socket open forever.
   */
  async capture(url: string, options: CaptureOptions = {}): Promise<Capture | undefined> {
    const {
      width = 1280,
      height = 800,
      scale = 0.5,
      settleMs = 1400,
      timeoutMs = 15_000,
    } = options;

    let targetId: string | undefined;
    let sessionId: string | undefined;

    const work = async (): Promise<Capture | undefined> => {
      try {
        await this.#start();
      } catch (err) {
        // The browser is unusable; every later capture will fail identically.
        this.startupFailed = true;
        throw err;
      }

      // No width/height here: Chrome rejects them outside new-window creation
      // ("Target position can only be set for new windows"). The viewport is
      // set below via Emulation instead, which is what actually matters.
      const created = (await this.#send('Target.createTarget', {
        url: 'about:blank',
      })) as { targetId: string };
      targetId = created.targetId;

      const attached = (await this.#send('Target.attachToTarget', {
        targetId,
        flatten: true,
      })) as { sessionId: string };
      sessionId = attached.sessionId;

      await this.#send('Page.enable', {}, sessionId);
      // Lay out at full desktop width but rasterise smaller, so the thumbnail
      // shows the real desktop layout rather than a mobile breakpoint.
      await this.#send(
        'Emulation.setDeviceMetricsOverride',
        { width, height, deviceScaleFactor: scale, mobile: false },
        sessionId,
      );

      // Navigation may never "finish" on a live page (HMR sockets, SSE), so we
      // do not wait for quiet - but we do read the result when it arrives,
      // because Chrome happily renders and screenshots its own error page. A
      // crisp PNG of "This site can't be reached" is worse than no thumbnail,
      // so a reported errorText aborts the capture.
      const navigation = (await Promise.race([
        this.#send('Page.navigate', { url }, sessionId),
        new Promise((r) => setTimeout(() => r(undefined), 6000)),
      ])) as { errorText?: string } | undefined;

      if (navigation?.errorText) return undefined;

      await new Promise((r) => setTimeout(r, settleMs));

      // JPEG, not PNG: these are thumbnails, and a PNG of a page with any
      // texture or gradient is an order of magnitude larger for no benefit.
      const shot = (await this.#send(
        'Page.captureScreenshot',
        { format: 'jpeg', quality: 76, captureBeyondViewport: false },
        sessionId,
      )) as { data?: string };

      if (!shot.data) return undefined;
      return { bytes: Buffer.from(shot.data, 'base64'), contentType: 'image/jpeg' };
    };

    try {
      return await Promise.race([
        work(),
        new Promise<Capture | undefined>((_, reject) =>
          setTimeout(() => reject(new Error('capture timeout')), timeoutMs),
        ),
      ]);
    } catch (err) {
      this.lastError = err instanceof Error ? err.message : String(err);
      return undefined;
    } finally {
      if (targetId) {
        // Always reclaim the tab, even on the timeout path.
        await this.#send('Target.closeTarget', { targetId }).catch(() => undefined);
      }
    }
  }

  async close(): Promise<void> {
    try {
      this.#ws?.close();
    } catch {
      // Already gone.
    }
    this.#ws = undefined;

    const proc = this.#proc;
    this.#proc = undefined;
    if (proc && !proc.killed) {
      proc.kill();
      // Give it a moment to exit cleanly before forcing it.
      await new Promise((r) => setTimeout(r, 200));
      if (!proc.killed) proc.kill('SIGKILL');
    }

    if (this.#profileDir) {
      await rm(this.#profileDir, { recursive: true, force: true }).catch(() => undefined);
      this.#profileDir = undefined;
    }
  }
}
