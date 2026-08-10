import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { PortRecord } from '../shared/types.ts';

/** Bump when the on-disk shape changes incompatibly; old files are discarded. */
const CACHE_VERSION = 1;

export interface CacheState {
  version: number;
  updatedAt: number;
  /** When tier 3 last completed, so we know whether to run it again. */
  lastFullSweep: number;
  records: PortRecord[];
}

export function emptyState(): CacheState {
  return { version: CACHE_VERSION, updatedAt: 0, lastFullSweep: 0, records: [] };
}

export function cacheDir(): string {
  const xdg = process.env['XDG_CACHE_HOME'];
  const base = xdg && xdg.trim() !== '' ? xdg : path.join(os.homedir(), '.cache');
  return path.join(base, 'ports');
}

export function statePath(): string {
  return path.join(cacheDir(), 'state.json');
}

export function faviconDir(): string {
  return path.join(cacheDir(), 'favicons');
}

/** Reject anything that is not a plausible record rather than trusting the file. */
function isRecord(value: unknown): value is PortRecord {
  if (!value || typeof value !== 'object') return false;
  const r = value as Partial<PortRecord>;
  return (
    typeof r.port === 'number' &&
    Number.isInteger(r.port) &&
    r.port > 0 &&
    r.port <= 65535 &&
    typeof r.id === 'string' &&
    Array.isArray(r.addresses)
  );
}

/**
 * Read cached state.
 *
 * A missing, unreadable, corrupt or version-mismatched file is not an error
 * worth surfacing: the cache is an optimisation, and starting cold is always
 * correct. We only ever degrade to a full scan.
 */
export async function loadCache(): Promise<CacheState> {
  try {
    const raw = await readFile(statePath(), 'utf8');
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return emptyState();

    const state = parsed as Partial<CacheState>;
    if (state.version !== CACHE_VERSION) return emptyState();

    const records = Array.isArray(state.records) ? state.records.filter(isRecord) : [];
    return {
      version: CACHE_VERSION,
      updatedAt: typeof state.updatedAt === 'number' ? state.updatedAt : 0,
      lastFullSweep: typeof state.lastFullSweep === 'number' ? state.lastFullSweep : 0,
      records,
    };
  } catch {
    return emptyState();
  }
}

/**
 * Write state atomically.
 *
 * Writing to a sibling temp file and renaming means a crash mid-write leaves
 * the previous cache intact instead of a truncated JSON file. The temp name
 * includes the pid so two instances cannot clobber each other's partial write.
 */
export async function saveCache(state: CacheState): Promise<void> {
  const target = statePath();
  const tmp = `${target}.${process.pid}.tmp`;

  try {
    await mkdir(cacheDir(), { recursive: true });
    const payload: CacheState = { ...state, version: CACHE_VERSION, updatedAt: Date.now() };
    await writeFile(tmp, JSON.stringify(payload), 'utf8');
    await rename(tmp, target);
  } catch {
    // A read-only or full disk should never take the scan down with it.
    try {
      await unlink(tmp);
    } catch {
      // Nothing to clean up.
    }
  }
}

/**
 * Coalescing writer for the long-running server, where records change
 * constantly and every change would otherwise mean a disk write.
 */
export function createCacheWriter(delayMs = 1000): {
  schedule: (state: CacheState) => void;
  flush: () => Promise<void>;
} {
  let timer: NodeJS.Timeout | undefined;
  let pending: CacheState | undefined;
  let writing: Promise<void> = Promise.resolve();

  const write = async () => {
    const state = pending;
    pending = undefined;
    timer = undefined;
    if (!state) return;
    writing = saveCache(state);
    await writing;
  };

  return {
    schedule(state: CacheState) {
      pending = state;
      if (timer) return;
      timer = setTimeout(() => void write(), delayMs);
      // Never hold the process open just to flush the cache.
      timer.unref?.();
    },
    async flush() {
      if (timer) {
        clearTimeout(timer);
        timer = undefined;
      }
      await write();
      await writing;
    },
  };
}
