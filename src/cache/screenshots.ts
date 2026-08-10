import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { cacheDir } from './store.ts';

/** Thumbnails are JPEG; anything much larger than this is a capture bug. */
const MAX_BYTES = 2 * 1024 * 1024;

export function screenshotDir(): string {
  return path.join(cacheDir(), 'shots');
}

function blobPath(hash: string): string {
  return path.join(screenshotDir(), `${hash}.jpg`);
}

export function hashBytes(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex').slice(0, 16);
}

export async function storeScreenshot(bytes: Buffer): Promise<string | undefined> {
  if (bytes.length === 0 || bytes.length > MAX_BYTES) return undefined;
  const hash = hashBytes(bytes);
  try {
    await mkdir(screenshotDir(), { recursive: true });
    await writeFile(blobPath(hash), bytes);
    return hash;
  } catch {
    // A thumbnail is a nicety; never fail a scan over one.
    return undefined;
  }
}

export async function readScreenshot(hash: string): Promise<Buffer | undefined> {
  // The hash arrives from an HTTP path, so reject anything that is not one of
  // our own hex digests before it reaches the filesystem.
  if (!/^[0-9a-f]{16}$/.test(hash)) return undefined;
  try {
    return await readFile(blobPath(hash));
  } catch {
    return undefined;
  }
}

/**
 * Delete thumbnails no record points at any more.
 *
 * Screenshots are content-addressed, so a page that changes leaves its old
 * image behind. Without this the cache directory grows without bound.
 */
export async function pruneScreenshots(keep: ReadonlySet<string>): Promise<number> {
  let removed = 0;
  try {
    const files = await readdir(screenshotDir());
    for (const file of files) {
      const hash = file.replace(/\.jpg$/, '');
      if (keep.has(hash)) continue;
      try {
        await unlink(path.join(screenshotDir(), file));
        removed++;
      } catch {
        // Someone else may have removed it already.
      }
    }
  } catch {
    // No directory yet.
  }
  return removed;
}
