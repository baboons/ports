import { createHash } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { faviconDir } from './store.ts';

/** Icons are small; anything larger is not a favicon and we refuse it. */
const MAX_FAVICON_BYTES = 256 * 1024;
const FETCH_TIMEOUT = 3000;

const ALLOWED_TYPES = [
  'image/png',
  'image/x-icon',
  'image/vnd.microsoft.icon',
  'image/svg+xml',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'image/avif',
];

export interface Favicon {
  hash: string;
  contentType: string;
  bytes: Buffer;
}

/** Sniff the format, because plenty of servers mislabel favicons. */
function detectType(bytes: Buffer, declared: string | undefined): string | undefined {
  if (bytes.length < 4) return undefined;

  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
    return 'image/png';
  }
  if (bytes[0] === 0x00 && bytes[1] === 0x00 && bytes[2] === 0x01 && bytes[3] === 0x00) {
    return 'image/x-icon';
  }
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'image/jpeg';
  if (bytes.subarray(0, 3).toString('latin1') === 'GIF') return 'image/gif';
  if (
    bytes.subarray(0, 4).toString('latin1') === 'RIFF' &&
    bytes.subarray(8, 12).toString('latin1') === 'WEBP'
  ) {
    return 'image/webp';
  }

  // SVG is text, and may open with a comment, doctype or XML declaration.
  const head = bytes.subarray(0, 256).toString('utf8').trimStart();
  if (head.startsWith('<?xml') || head.startsWith('<svg') || head.includes('<svg')) {
    return 'image/svg+xml';
  }

  const base = declared?.split(';')[0]?.trim().toLowerCase();
  return base && ALLOWED_TYPES.includes(base) ? base : undefined;
}

/**
 * Fetch an icon over plain HTTP or TLS, ignoring certificate problems.
 *
 * This has to happen server-side. A browser asked to load an icon straight
 * from a self-signed HTTPS dev server refuses it, so the page would show a
 * broken image for exactly the servers this tool exists to catalogue.
 */
export function fetchFavicon(url: string, signal?: AbortSignal): Promise<Favicon | undefined> {
  return new Promise((resolve) => {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return resolve(undefined);
    }

    const secure = parsed.protocol === 'https:';
    if (!secure && parsed.protocol !== 'http:') return resolve(undefined);

    const mod = secure ? https : http;
    const req = mod.request(
      url,
      {
        method: 'GET',
        ...(secure ? { rejectUnauthorized: false } : {}),
        headers: { accept: 'image/*,*/*;q=0.8', connection: 'close' },
        timeout: FETCH_TIMEOUT,
        ...(signal ? { signal } : {}),
      },
      (res) => {
        if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          return resolve(undefined);
        }

        const chunks: Buffer[] = [];
        let size = 0;
        let aborted = false;

        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_FAVICON_BYTES) {
            aborted = true;
            res.destroy();
            return;
          }
          chunks.push(chunk);
        });

        const done = () => {
          if (aborted || chunks.length === 0) return resolve(undefined);
          const bytes = Buffer.concat(chunks);
          const contentType = detectType(bytes, res.headers['content-type']);
          // A 200 that is really an HTML error page is a very common way for
          // /favicon.ico to "succeed"; the sniff is what catches it.
          if (!contentType) return resolve(undefined);
          resolve({
            hash: createHash('sha256').update(bytes).digest('hex').slice(0, 16),
            contentType,
            bytes,
          });
        };

        res.on('end', done);
        res.on('close', done);
        res.on('error', () => resolve(undefined));
      },
    );

    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(undefined));
    req.end();
  });
}

function blobPath(hash: string): string {
  return path.join(faviconDir(), hash);
}

function metaPath(hash: string): string {
  return path.join(faviconDir(), `${hash}.type`);
}

/** Persist icon bytes so the UI can serve them from its own origin. */
export async function storeFavicon(icon: Favicon): Promise<void> {
  try {
    await mkdir(faviconDir(), { recursive: true });
    await Promise.all([
      writeFile(blobPath(icon.hash), icon.bytes),
      writeFile(metaPath(icon.hash), icon.contentType, 'utf8'),
    ]);
  } catch {
    // Losing a cached icon is cosmetic; never fail a scan over it.
  }
}

export async function readFavicon(
  hash: string,
): Promise<{ bytes: Buffer; contentType: string } | undefined> {
  // Hashes are hex from our own hashing, but this value reaches us from an
  // HTTP path later, so refuse anything that could escape the directory.
  if (!/^[0-9a-f]{16}$/.test(hash)) return undefined;
  try {
    const [bytes, contentType] = await Promise.all([
      readFile(blobPath(hash)),
      readFile(metaPath(hash), 'utf8').catch(() => 'application/octet-stream'),
    ]);
    return { bytes, contentType: contentType.trim() };
  } catch {
    return undefined;
  }
}

/** Fetch and cache in one step, returning the hash to store on the record. */
export async function cacheFavicon(
  url: string,
  signal?: AbortSignal,
): Promise<string | undefined> {
  const icon = await fetchFavicon(url, signal);
  if (!icon) return undefined;
  await storeFavicon(icon);
  return icon.hash;
}
