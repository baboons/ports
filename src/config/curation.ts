import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { PortRecord } from '../shared/types.ts';

/**
 * What the user has chosen not to see.
 *
 * This lives in config, not cache: it is intent, not derived data, so it must
 * survive `rm -rf ~/.cache/ports` and be safe to hand-edit. It is also kept in
 * its own file rather than merged into config.json, so writing a hide rule can
 * never rewrite (and reformat, or lose comments in) a file the user maintains.
 */

const CURATION_VERSION = 1;

export interface Curation {
  version: number;
  /** Exact ports to hide. What the UI's hide button writes. */
  hiddenPorts: number[];
  /** Inclusive ranges as "from-to", for blocks like an app's IPC region. */
  hiddenRanges: string[];
  /** Case-insensitive substrings matched against the process name/command. */
  hiddenCommands: string[];
}

export function emptyCuration(): Curation {
  return { version: CURATION_VERSION, hiddenPorts: [], hiddenRanges: [], hiddenCommands: [] };
}

export function configDir(): string {
  const xdg = process.env['XDG_CONFIG_HOME'];
  const base = xdg && xdg.trim() !== '' ? xdg : path.join(os.homedir(), '.config');
  return path.join(base, 'ports');
}

export function curationPath(): string {
  return path.join(configDir(), 'curation.json');
}

function asPortList(value: unknown): number[] {
  if (!Array.isArray(value)) return [];
  return [
    ...new Set(
      value
        .map((entry) => (typeof entry === 'number' ? entry : Number.parseInt(String(entry), 10)))
        .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535),
    ),
  ].sort((a, b) => a - b);
}

function asStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [
    ...new Set(
      value
        .filter((entry): entry is string => typeof entry === 'string')
        .map((entry) => entry.trim())
        .filter(Boolean),
    ),
  ];
}

/** Never throws: a broken or absent file just means nothing is hidden. */
export async function loadCuration(): Promise<Curation> {
  try {
    const raw = await readFile(curationPath(), 'utf8');
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return emptyCuration();

    const value = parsed as Partial<Curation>;
    return {
      version: CURATION_VERSION,
      hiddenPorts: asPortList(value.hiddenPorts),
      hiddenRanges: asStringList(value.hiddenRanges).filter((r) => parseRange(r) !== undefined),
      hiddenCommands: asStringList(value.hiddenCommands),
    };
  } catch {
    return emptyCuration();
  }
}

export async function saveCuration(curation: Curation): Promise<void> {
  const target = curationPath();
  const tmp = `${target}.${process.pid}.tmp`;
  try {
    await mkdir(configDir(), { recursive: true });
    // Pretty-printed because this file is meant to be edited by hand.
    await writeFile(tmp, `${JSON.stringify({ ...curation, version: CURATION_VERSION }, null, 2)}\n`, 'utf8');
    await rename(tmp, target);
  } catch {
    try {
      await unlink(tmp);
    } catch {
      // Nothing to clean up.
    }
  }
}

/** "3000-3010" -> [3000, 3010]. Undefined when malformed. */
export function parseRange(value: string): [number, number] | undefined {
  const match = /^\s*(\d{1,5})\s*-\s*(\d{1,5})\s*$/.exec(value);
  if (!match) return undefined;
  const from = Number.parseInt(match[1]!, 10);
  const to = Number.parseInt(match[2]!, 10);
  if (!Number.isInteger(from) || !Number.isInteger(to)) return undefined;
  if (from < 1 || to > 65535 || from > to) return undefined;
  return [from, to];
}

export type HideReason = 'port' | 'range' | 'command';

/**
 * Why this record is hidden, or undefined if it is not.
 *
 * Returning the reason rather than a boolean lets the UI explain itself: a row
 * hidden by a hand-written command rule cannot be restored by un-hiding one
 * port, and saying so beats a button that appears to do nothing.
 */
export function hideReasonFor(
  record: Pick<PortRecord, 'port' | 'process'>,
  curation: Curation,
): HideReason | undefined {
  if (curation.hiddenPorts.includes(record.port)) return 'port';

  for (const raw of curation.hiddenRanges) {
    const range = parseRange(raw);
    if (range && record.port >= range[0] && record.port <= range[1]) return 'range';
  }

  if (curation.hiddenCommands.length > 0) {
    const haystack = `${record.process?.name ?? ''} ${record.process?.command ?? ''}`.toLowerCase();
    if (haystack.trim()) {
      for (const needle of curation.hiddenCommands) {
        if (haystack.includes(needle.toLowerCase())) return 'command';
      }
    }
  }

  return undefined;
}

export function isHidden(
  record: Pick<PortRecord, 'port' | 'process'>,
  curation: Curation,
): boolean {
  return hideReasonFor(record, curation) !== undefined;
}

/** Add a port to the hidden list. Returns the updated curation. */
export function withHidden(curation: Curation, port: number): Curation {
  if (curation.hiddenPorts.includes(port)) return curation;
  return { ...curation, hiddenPorts: [...curation.hiddenPorts, port].sort((a, b) => a - b) };
}

/**
 * Remove a port from the hidden list.
 *
 * Only touches `hiddenPorts`: a range or command rule is a broader statement
 * the user wrote deliberately, and silently rewriting it to un-hide one port
 * would be a surprising thing for a small button to do.
 */
export function withoutHidden(curation: Curation, port: number): Curation {
  return { ...curation, hiddenPorts: curation.hiddenPorts.filter((p) => p !== port) };
}
