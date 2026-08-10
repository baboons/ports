import net from 'node:net';

export interface SweepOptions {
  host?: string;
  /** Max sockets in flight. Loopback tolerates a lot; the OS fd limit is the ceiling. */
  concurrency?: number;
  /** Per-connection budget in ms. Loopback answers or resets almost instantly. */
  timeout?: number;
  signal?: AbortSignal;
  /** Called as each port resolves, open or not, so callers can stream progress. */
  onResult?: (port: number, open: boolean) => void;
  onProgress?: (scanned: number, total: number) => void;
}

/**
 * Errors that mean "the machine ran out of something", not "the port is shut".
 *
 * Treating these as closed would silently drop real servers from the results
 * whenever the box is under pressure, which is the worst kind of bug for an
 * inventory tool: a quiet false negative. We retry them instead.
 */
const EXHAUSTION_CODES = new Set([
  'EMFILE', // process fd limit
  'ENFILE', // system-wide fd limit
  'ENOBUFS', // kernel buffer pressure
  'EADDRNOTAVAIL', // ephemeral port range exhausted
  'EADDRINUSE',
]);

type ProbeOutcome = 'open' | 'closed' | 'exhausted';

function attemptConnect(
  port: number,
  host: string,
  timeout: number,
  signal?: AbortSignal,
): Promise<ProbeOutcome> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve('closed');

    const socket = new net.Socket();
    let settled = false;

    const finish = (outcome: ProbeOutcome) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      socket.removeAllListeners();
      socket.destroy();
      resolve(outcome);
    };

    const onAbort = () => finish('closed');
    signal?.addEventListener('abort', onAbort, { once: true });

    socket.setTimeout(timeout);
    socket.once('connect', () => finish('open'));
    socket.once('timeout', () => finish('closed'));
    socket.once('error', (err: NodeJS.ErrnoException) => {
      finish(err.code && EXHAUSTION_CODES.has(err.code) ? 'exhausted' : 'closed');
    });

    socket.connect(port, host);
  });
}

/**
 * Is something accepting TCP connections on this port?
 *
 * A closed loopback port RSTs immediately (measured: all 65523 closed ports on
 * a real machine answered ECONNREFUSED, none timed out), so the timeout only
 * applies to filtered ports, which on localhost is rare. That is what makes
 * sweeping the whole range affordable.
 */
export async function checkPort(
  port: number,
  host = '127.0.0.1',
  timeout = 300,
  signal?: AbortSignal,
): Promise<boolean> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const outcome = await attemptConnect(port, host, timeout, signal);
    if (outcome === 'open') return true;
    if (outcome === 'closed') return false;
    if (signal?.aborted) return false;
    // Back off to let descriptors and ephemeral ports drain, then retry.
    await new Promise((r) => setTimeout(r, 50 * (attempt + 1)));
  }
  return false;
}

/**
 * Connect-scan a list of ports with a bounded number of sockets in flight.
 *
 * Implemented as N long-lived workers pulling from a shared cursor rather than
 * chunked batches: a batch would stall on its slowest port before starting the
 * next one, which on a 65535-port sweep adds up badly.
 */
export async function sweepPorts(
  ports: number[],
  options: SweepOptions = {},
): Promise<number[]> {
  const {
    host = '127.0.0.1',
    concurrency = 256,
    timeout = 300,
    signal,
    onResult,
    onProgress,
  } = options;

  const open: number[] = [];
  const total = ports.length;
  let cursor = 0;
  let scanned = 0;

  const worker = async (): Promise<void> => {
    while (cursor < total) {
      if (signal?.aborted) return;
      const index = cursor++;
      const port = ports[index];
      if (port === undefined) return;

      const isOpen = await checkPort(port, host, timeout, signal);
      scanned++;

      if (isOpen) open.push(port);
      onResult?.(port, isOpen);
      // Reporting every single port would flood the SSE stream; the caller
      // decides how to throttle, we just report often enough to be smooth.
      if (scanned % 64 === 0 || scanned === total) onProgress?.(scanned, total);
    }
  };

  const workers = Array.from(
    { length: Math.min(concurrency, Math.max(total, 1)) },
    () => worker(),
  );
  await Promise.all(workers);

  open.sort((a, b) => a - b);
  return open;
}

/** Every port in 1-65535, minus any we already know about. */
export function fullRange(exclude: Iterable<number> = []): number[] {
  const skip = new Set(exclude);
  const ports: number[] = [];
  for (let p = 1; p <= 65535; p++) {
    if (!skip.has(p)) ports.push(p);
  }
  return ports;
}
