import type { PortRecord } from '../shared/types.ts';
import { Screenshotter } from './browser.ts';
import { storeScreenshot } from '../cache/screenshots.ts';

/** Re-shoot a page that has not changed at most this often. */
export const SCREENSHOT_TTL = 15 * 60_000;

const VIEWPORT_WIDTH = 1280;
const VIEWPORT_HEIGHT = 800;
const SCALE = 0.5;

/**
 * Is this record worth a thumbnail?
 *
 * Only pages a person could actually open: a live 2xx HTML response. Shooting
 * a 404, a JSON API or a non-HTTP listener would spend seconds of browser time
 * to produce a picture of an error page or a wall of raw text.
 */
/**
 * Will loading this port's root actually put a page on screen?
 *
 * A plain 2xx obviously qualifies. A 3xx does too, but only when the probe
 * followed it to a 2xx: `fetchHead` follows redirects within loopback only, so
 * a recorded `finalStatus` is proof the chain stayed on this machine. That
 * distinction matters because Chrome follows redirects on its own — without
 * the check, a dev server pointing at an external login page would have us
 * fetching and storing a picture of a public website.
 */
function rendersSomething(record: PortRecord): boolean {
  const status = record.http?.status;
  if (typeof status !== 'number') return false;

  if (status >= 200 && status < 300) return true;

  if (status >= 300 && status < 400) {
    const final = record.http?.finalStatus;
    return typeof final === 'number' && final >= 200 && final < 300;
  }

  return false;
}

export function shouldCapture(record: PortRecord, now = Date.now()): boolean {
  if (!record.alive) return false;
  if (record.protocol !== 'http' && record.protocol !== 'https') return false;
  if (!rendersSomething(record)) return false;

  const contentType = record.http?.contentType ?? '';
  // An empty content-type is ambiguous; a title means something rendered HTML.
  if (contentType && !contentType.includes('html')) return false;
  if (!contentType && !record.meta?.title) return false;

  const shot = record.screenshot;
  if (!shot) return true;
  // The page changed since we last looked at it.
  if (shot.fingerprint !== record.fingerprint) return true;
  return now - shot.capturedAt >= SCREENSHOT_TTL;
}

function urlFor(record: PortRecord): string {
  const host = record.probedAddress.includes(':')
    ? `[${record.probedAddress}]`
    : record.probedAddress;
  return `${record.protocol === 'https' ? 'https' : 'http'}://${host}:${record.port}/`;
}

export interface CaptureRunOptions {
  /** Skip this port; used so the board never photographs itself. */
  skipPort?: number;
  signal?: AbortSignal;
  /** Called per successful capture so the UI can update incrementally. */
  onCaptured?: (record: PortRecord) => void;
  /** Called once if capture is failing wholesale, with the reason. */
  onProblem?: (reason: string) => void;
  /** Called on the first success, so a stale problem report can be cleared. */
  onWorking?: () => void;
}

/**
 * Capture thumbnails for everything eligible, one at a time.
 *
 * Sequential on purpose: each capture drives a real browser tab, and running
 * several at once competes with the very dev servers we are photographing.
 * The browser process is started once and reused across the whole batch.
 */
export async function captureAll(
  records: Iterable<PortRecord>,
  options: CaptureRunOptions = {},
): Promise<number> {
  const { skipPort, signal, onCaptured, onProblem, onWorking } = options;

  const due = [...records].filter(
    (record) => record.port !== skipPort && shouldCapture(record),
  );
  if (due.length === 0) return 0;

  const shooter = await Screenshotter.create();
  // No Chromium on this machine: everything else still works, there are just
  // no thumbnails.
  if (!shooter) return 0;

  let captured = 0;
  let failures = 0;
  try {
    for (const record of due) {
      if (signal?.aborted) break;

      const shot = await shooter.capture(urlFor(record), {
        width: VIEWPORT_WIDTH,
        height: VIEWPORT_HEIGHT,
        scale: SCALE,
      });
      if (!shot) {
        failures++;
        // Only a browser that will not start is a wholesale problem. A single
        // page that stalls says nothing about the next one, so keep going.
        if (shooter.startupFailed) {
          onProblem?.(shooter.lastError ?? 'browser failed to start');
          break;
        }
        continue;
      }

      const hash = await storeScreenshot(shot.bytes);
      if (!hash) continue;

      record.screenshot = {
        hash,
        capturedAt: Date.now(),
        width: Math.round(VIEWPORT_WIDTH * SCALE),
        height: Math.round(VIEWPORT_HEIGHT * SCALE),
        ...(record.fingerprint ? { fingerprint: record.fingerprint } : {}),
      };
      captured++;
      // Proof the pipeline works, whatever individual pages did earlier.
      onWorking?.();
      onCaptured?.(record);
    }
  } finally {
    await shooter.close();
  }

  return captured;
}
