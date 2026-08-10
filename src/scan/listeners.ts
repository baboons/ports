import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { Family, Listener } from '../shared/types.ts';

const exec = promisify(execFile);

/**
 * lsof emits records in field mode grouped by process: the `p`/`c`/`L` fields
 * appear once, then one `f`/`t`/`n` group per file descriptor. So we carry the
 * process fields forward and emit a listener each time we see an address.
 */
export function parseLsof(output: string): Listener[] {
  const listeners: Listener[] = [];
  const seen = new Set<string>();

  let pid: number | undefined;
  let command: string | undefined;
  let user: string | undefined;
  let family: Family | undefined;

  for (const line of output.split('\n')) {
    if (line.length < 2) continue;
    const tag = line[0]!;
    const value = line.slice(1);

    switch (tag) {
      case 'p': {
        pid = Number.parseInt(value, 10);
        // A new process resets the per-descriptor state.
        family = undefined;
        break;
      }
      case 'c':
        command = value;
        break;
      case 'L':
        user = value;
        break;
      case 't':
        family = value === 'IPv6' ? 'ipv6' : 'ipv4';
        break;
      case 'n': {
        const parsed = parseAddress(value);
        if (!parsed) break;
        // A single process often holds the same address on many descriptors
        // (nginx workers, node cluster). Collapse them.
        const key = `${parsed.address}:${parsed.port}`;
        if (seen.has(key)) break;
        seen.add(key);
        listeners.push({
          port: parsed.port,
          address: parsed.address,
          family: family ?? (parsed.address.includes(':') ? 'ipv6' : 'ipv4'),
          ...(pid !== undefined && Number.isFinite(pid) ? { pid } : {}),
          ...(command ? { command } : {}),
          ...(user ? { user } : {}),
        });
        break;
      }
      default:
        break;
    }
  }

  return listeners;
}

/**
 * Handles the three shapes lsof produces for a listening socket:
 *   127.0.0.1:8080   *:52259   [::1]:18789
 */
function parseAddress(raw: string): { address: string; port: number } | null {
  // Strip a trailing state annotation if -s didn't already filter it.
  const value = raw.replace(/\s*\(LISTEN\)\s*$/, '').trim();

  const lastColon = value.lastIndexOf(':');
  if (lastColon === -1) return null;

  const portRaw = value.slice(lastColon + 1);
  const port = Number.parseInt(portRaw, 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;

  let address = value.slice(0, lastColon);
  if (address.startsWith('[') && address.endsWith(']')) {
    address = address.slice(1, -1);
  }
  if (address === '' || address === '*') address = '0.0.0.0';

  return { address, port };
}

/**
 * Tier 1: enumerate listening sockets from the process table.
 *
 * Unprivileged lsof only reports the current user's processes, so this misses
 * root-owned listeners; the connect sweep in tiers 2/3 covers that gap.
 * Never throws - a missing or failing lsof just means zero listeners.
 */
export async function enumerateListeners(): Promise<Listener[]> {
  try {
    const { stdout } = await exec(
      'lsof',
      ['-nP', '-iTCP', '-sTCP:LISTEN', '-FpcnLt'],
      { timeout: 5000, maxBuffer: 8 * 1024 * 1024 },
    );
    return parseLsof(stdout);
  } catch (err) {
    // lsof exits non-zero when it has partial results (e.g. permission denied
    // on some descriptors) but still prints usable output on stdout.
    const stdout = (err as { stdout?: string }).stdout;
    if (typeof stdout === 'string' && stdout.length > 0) {
      return parseLsof(stdout);
    }
    return [];
  }
}

/** True when we can see other users' sockets, which widens tier 1 coverage. */
export function isPrivileged(): boolean {
  return typeof process.getuid === 'function' && process.getuid() === 0;
}
