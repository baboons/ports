import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import type { IncomingMessage } from 'node:http';
import type { TLSSocket } from 'node:tls';
import type { HttpInfo, PageMeta, Protocol, TlsInfo } from '../shared/types.ts';
import { detectFramework, extractMeta } from './metadata.ts';

/** Only the head matters, and unbounded reads on a log-streaming endpoint hurt. */
const MAX_BODY_BYTES = 64 * 1024;
// Tuned against real silent listeners (Apple's rapportd accepts and then says
// nothing). Anything that has not spoken by now is not going to.
const SNIFF_TIMEOUT = 800;
// Generous for loopback, where a healthy server answers in single-digit ms.
const REQUEST_TIMEOUT = 2500;
const MAX_REDIRECTS = 3;
/**
 * Ceiling on a single port's entire probe, redirects included. Without it a
 * chain of slow hops can hold a probe worker for far longer than any one
 * request timeout suggests.
 *
 * Every genuine HTTP server measured on a real machine replied inside 600ms,
 * so this leaves ample headroom. The ports that reach it are ones like a
 * non-HTTP service that accepts the socket and then stalls - they are going to
 * end up classified `tcp` regardless, so waiting longer buys nothing.
 */
const PROBE_DEADLINE = 3000;

export interface ProbeResult {
  protocol: Protocol;
  http?: HttpInfo;
  meta?: PageMeta;
  tls?: TlsInfo;
  probeMs: number;
  error?: string;
}

/**
 * Decide what a port is speaking by sending a plaintext HTTP request and
 * looking at the first bytes of the reply.
 *
 *   "HTTP/"      -> plaintext HTTP
 *   0x16 / 0x15  -> TLS handshake or alert; our cleartext GET was not a valid
 *                   ClientHello, so a TLS server answers with an alert
 *   RST, no data -> many TLS stacks just drop garbage; worth a TLS retry
 *   anything else-> some other protocol, or a banner server like SSH/SMTP
 *
 * Returns a hint rather than a verdict; `probePort` acts on it.
 */
function sniff(
  port: number,
  host: string,
  signal?: AbortSignal,
): Promise<'http' | 'maybe-tls' | 'other' | 'closed'> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve('closed');

    const socket = new net.Socket();
    let settled = false;
    let received = Buffer.alloc(0);
    let connected = false;

    const finish = (result: 'http' | 'maybe-tls' | 'other' | 'closed') => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      socket.removeAllListeners();
      socket.destroy();
      resolve(result);
    };

    const classify = () => {
      if (received.length === 0) {
        // Connected, accepted our request, said nothing. Either a client-speaks-
        // first protocol or a TLS server that ignored us. Worth one TLS attempt.
        return finish(connected ? 'maybe-tls' : 'closed');
      }
      const first = received[0]!;
      if (first === 0x16 || first === 0x15) return finish('maybe-tls');

      const head = received.subarray(0, 5).toString('latin1');
      if (head.startsWith('HTTP/')) return finish('http');

      return finish('other');
    };

    const onAbort = () => finish('closed');
    signal?.addEventListener('abort', onAbort, { once: true });

    socket.setTimeout(SNIFF_TIMEOUT);

    socket.once('connect', () => {
      connected = true;
      socket.write(`GET / HTTP/1.1\r\nHost: ${host}:${port}\r\nConnection: close\r\n\r\n`);
    });

    socket.on('data', (chunk: Buffer) => {
      received = Buffer.concat([received, chunk]);
      // The verdict only needs the first few bytes.
      if (received.length >= 8) classify();
    });

    socket.once('timeout', () => (connected ? classify() : finish('closed')));
    socket.once('end', classify);
    socket.once('close', classify);
    socket.once('error', (err: NodeJS.ErrnoException) => {
      if (!connected) return finish('closed');
      // A reset after a successful connect is the classic "you spoke the wrong
      // protocol at me" signal.
      if (err.code === 'ECONNRESET') return finish('maybe-tls');
      classify();
    });

    socket.connect(port, host);
  });
}

interface FetchOutcome {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  tls?: TlsInfo;
  finalUrl: string;
  redirectTo?: string;
  firstStatus: number;
}

/** GET a URL, reading at most MAX_BODY_BYTES and following a few redirects. */
async function fetchHead(
  url: string,
  secure: boolean,
  signal?: AbortSignal,
  depth = 0,
  firstStatus?: number,
  firstRedirect?: string,
): Promise<FetchOutcome> {
  const outcome = await new Promise<FetchOutcome>((resolve, reject) => {
    const mod = secure ? https : http;
    const req = mod.request(
      url,
      {
        method: 'GET',
        // Dev servers overwhelmingly use self-signed or mkcert certs; refusing
        // them would make the tool useless for exactly the case it exists for.
        ...(secure ? { rejectUnauthorized: false } : {}),
        headers: {
          // Some servers content-negotiate; ask for HTML so we get a <title>.
          accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
          'user-agent': 'ports-scanner/0.1 (+localhost inventory)',
          connection: 'close',
        },
        timeout: REQUEST_TIMEOUT,
        signal,
      },
      (res: IncomingMessage) => {
        const chunks: Buffer[] = [];
        let size = 0;

        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size <= MAX_BODY_BYTES) {
            chunks.push(chunk);
          } else {
            // We have all the head we are going to need; stop paying for the rest.
            chunks.push(chunk.subarray(0, chunk.length - (size - MAX_BODY_BYTES)));
            res.destroy();
          }
        });

        const done = () => {
          const headers: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (v === undefined) continue;
            headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
          }

          let tls: TlsInfo | undefined;
          if (secure) tls = readCert(res.socket as TLSSocket);

          resolve({
            status: res.statusCode ?? 0,
            statusText: res.statusMessage ?? '',
            headers,
            body: Buffer.concat(chunks).toString('utf8'),
            ...(tls ? { tls } : {}),
            finalUrl: url,
            firstStatus: firstStatus ?? res.statusCode ?? 0,
            ...(firstRedirect ? { redirectTo: firstRedirect } : {}),
          });
        };

        res.on('end', done);
        res.on('close', done);
        res.on('error', reject);
      },
    );

    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });

  // Follow redirects so the index shows the app's real title rather than the
  // empty body of a 302 to /login.
  const location = outcome.headers['location'];
  if (
    location &&
    outcome.status >= 300 &&
    outcome.status < 400 &&
    depth < MAX_REDIRECTS
  ) {
    let next: URL;
    try {
      next = new URL(location, url);
    } catch {
      return outcome;
    }
    // Only follow within localhost; an external redirect is a finding in itself.
    if (isLoopback(next.hostname)) {
      try {
        return await fetchHead(
          next.toString(),
          next.protocol === 'https:',
          signal,
          depth + 1,
          outcome.firstStatus,
          firstRedirect ?? location,
        );
      } catch {
        return outcome;
      }
    }
  }

  return outcome;
}

function isLoopback(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '::1' ||
    hostname === '[::1]' ||
    hostname.endsWith('.localhost')
  );
}

/** Certificate DN fields are string | string[] when a name repeats. */
function firstOf(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

function readCert(socket: TLSSocket): TlsInfo | undefined {
  try {
    const cert = socket.getPeerCertificate?.();
    if (!cert || Object.keys(cert).length === 0) return undefined;

    const subject = firstOf(cert.subject?.CN) ?? firstOf(cert.subject?.O);
    const issuer = firstOf(cert.issuer?.CN) ?? firstOf(cert.issuer?.O);
    const altNames = cert.subjectaltname
      ?.split(',')
      .map((s) => s.trim().replace(/^DNS:|^IP Address:/, ''))
      .filter(Boolean);

    return {
      ...(subject ? { subject } : {}),
      ...(issuer ? { issuer } : {}),
      ...(cert.valid_from ? { validFrom: cert.valid_from } : {}),
      ...(cert.valid_to ? { validTo: cert.valid_to } : {}),
      // Same CN on both ends, or no issuer at all, means nobody vouched for it.
      selfSigned: !issuer || issuer === subject,
      ...(socket.getProtocol?.() ? { protocol: socket.getProtocol()! } : {}),
      ...(altNames?.length ? { altNames } : {}),
    };
  } catch {
    return undefined;
  }
}

/** Full probe of a single open port: classify it, then describe it. */
export async function probePort(
  port: number,
  host = '127.0.0.1',
  outerSignal?: AbortSignal,
): Promise<ProbeResult> {
  const started = Date.now();
  const hostForUrl = host.includes(':') ? `[${host}]` : host;

  // Combine the caller's cancellation with our own deadline, so a pathological
  // port cannot pin a probe worker indefinitely.
  const deadline = AbortSignal.timeout(PROBE_DEADLINE);
  const signal = outerSignal
    ? AbortSignal.any([outerSignal, deadline])
    : deadline;

  const hint = await sniff(port, host, signal);

  if (hint === 'closed') {
    return { protocol: 'tcp', probeMs: Date.now() - started, error: 'no response' };
  }

  // No plaintext fallback on the maybe-tls path: the sniff already sent a
  // cleartext GET and it did not produce an HTTP reply, so repeating it can
  // only ever burn another full request timeout before failing the same way.
  const attempts: Array<{ secure: boolean }> =
    hint === 'maybe-tls'
      ? [{ secure: true }]
      : // 'http', or 'other' where the sniff saw a banner - one cheap
        // plaintext attempt, then we call it tcp.
        [{ secure: false }];

  let lastError: string | undefined;

  for (const { secure } of attempts) {
    const url = `${secure ? 'https' : 'http'}://${hostForUrl}:${port}/`;
    try {
      const res = await fetchHead(url, secure, signal);

      const httpInfo: HttpInfo = {
        status: res.firstStatus || res.status,
        ...(res.statusText ? { statusText: res.statusText } : {}),
        ...(res.redirectTo ? { redirectTo: res.redirectTo } : {}),
        // Recorded only when we actually followed the chain, which fetchHead
        // does only within loopback.
        ...(res.status !== res.firstStatus
          ? { finalStatus: res.status, finalUrl: res.finalUrl }
          : {}),
        ...(res.headers['server'] ? { server: res.headers['server'] } : {}),
        ...(res.headers['x-powered-by'] ? { poweredBy: res.headers['x-powered-by'] } : {}),
        ...(res.headers['content-type'] ? { contentType: res.headers['content-type'] } : {}),
      };
      const framework = detectFramework(res.headers);
      if (framework) httpInfo.framework = framework;

      const isHtml = (res.headers['content-type'] ?? '').includes('html') ||
        /<html|<!doctype html/i.test(res.body.slice(0, 512));
      const meta = isHtml ? extractMeta(res.body, res.finalUrl) : undefined;

      return {
        protocol: secure ? 'https' : 'http',
        http: httpInfo,
        ...(meta ? { meta } : {}),
        ...(res.tls ? { tls: res.tls } : {}),
        probeMs: Date.now() - started,
      };
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
    }
  }

  return {
    protocol: 'tcp',
    probeMs: Date.now() - started,
    ...(lastError ? { error: lastError } : {}),
  };
}
