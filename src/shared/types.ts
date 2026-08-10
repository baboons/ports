/**
 * The single source of truth for what we know about one listening port.
 * Shared between the scanner, the cache, the SSE stream and the UI.
 */

/** How a port was found. Lower tiers are faster and more trustworthy. */
export type DiscoveryTier =
  | 'cache' // 0: replayed from disk, not yet revalidated
  | 'lsof' // 1: enumerated from the process table
  | 'common' // 2: connect probe against the common dev-port list
  | 'sweep'; // 3: connect probe from the full 1-65535 range

/** What the port turned out to be speaking. */
export type Protocol =
  | 'http'
  | 'https'
  | 'tcp' // accepts connections but did not answer HTTP
  | 'unknown'; // not probed yet

export type Family = 'ipv4' | 'ipv6';

/** A raw listener as reported by the process table, before any probing. */
export interface Listener {
  port: number;
  /** Bind address exactly as reported, e.g. "127.0.0.1", "*", "::1". */
  address: string;
  family: Family;
  pid?: number;
  /** Short command name from lsof, e.g. "node". Truncated by lsof itself. */
  command?: string;
  user?: string;
}

/** Details of the TLS certificate presented by an https port. */
export interface TlsInfo {
  subject?: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  selfSigned: boolean;
  protocol?: string;
  altNames?: string[];
}

/** Everything we scraped out of the HTML head. */
export interface PageMeta {
  title?: string;
  description?: string;
  ogTitle?: string;
  ogDescription?: string;
  ogImage?: string;
  themeColor?: string;
  /** Absolute URL of the best favicon candidate we found. */
  faviconUrl?: string;
  /** Content hash of the fetched favicon bytes; the cache key. */
  faviconHash?: string;
}

/** A cached thumbnail of what the page actually looks like. */
export interface ScreenshotInfo {
  /** Content hash; the key for /api/screenshot/<hash>. */
  hash: string;
  capturedAt: number;
  width: number;
  height: number;
  /** Record fingerprint when captured, so a changed page triggers a re-shoot. */
  fingerprint?: string;
}

/** The process behind the port, resolved as far as we could get. */
export interface ProcessInfo {
  pid: number;
  /** Full command line from ps, may be long. */
  command?: string;
  /** Just the executable, e.g. "node". */
  name?: string;
  cwd?: string;
  user?: string;
  /** Resolved from a manifest in cwd, e.g. package.json "name". */
  projectName?: string;
  projectType?: 'node' | 'python' | 'rust' | 'go' | 'ruby' | 'php' | 'unknown';
}

/** The result of actually speaking HTTP to the port. */
export interface HttpInfo {
  status: number;
  statusText?: string;
  /** Where a 3xx pointed us. */
  redirectTo?: string;
  server?: string;
  poweredBy?: string;
  contentType?: string;
  /** Framework fingerprints picked out of the response headers. */
  framework?: string;
}

export interface PortRecord {
  /** Stable identity. The port number, as a string. */
  id: string;
  port: number;
  /**
   * Every bind address seen for this port. A dual-stacked dev server shows up
   * as both 127.0.0.1 and ::1; that is one server, so it is one record.
   */
  addresses: string[];
  /** The address we actually probed. */
  probedAddress: string;

  alive: boolean;
  protocol: Protocol;
  tier: DiscoveryTier;

  /** True while this record is a cache replay awaiting revalidation. */
  stale: boolean;
  /** This is the ports server itself. */
  isSelf: boolean;

  http?: HttpInfo;
  meta?: PageMeta;
  tls?: TlsInfo;
  process?: ProcessInfo;
  screenshot?: ScreenshotInfo;

  /** Epoch ms. */
  firstSeen: number;
  lastSeen: number;
  lastProbed: number;
  /** How many consecutive scans produced an identical fingerprint. */
  consecutiveStable: number;
  /** Hash of the volatile fields, used to decide whether to re-enrich. */
  fingerprint?: string;
  /** Wall time of the last successful probe, in ms. */
  probeMs?: number;
  error?: string;
}

/** Progress of an in-flight scan, streamed to the UI. */
export interface ScanProgress {
  phase: 'idle' | 'cache' | 'lsof' | 'common' | 'sweep' | 'probing' | 'done';
  scanned: number;
  total: number;
  found: number;
  startedAt: number;
  done: boolean;
}

/** Server -> client events over SSE. */
export type ServerEvent =
  | { type: 'snapshot'; records: PortRecord[]; progress: ScanProgress }
  | { type: 'upsert'; records: PortRecord[] }
  | { type: 'remove'; ids: string[] }
  | { type: 'scan'; progress: ScanProgress };

/** Shape persisted to ~/.cache/ports/state.json. */
export interface CacheFile {
  version: 1;
  updatedAt: number;
  records: PortRecord[];
}

export function portId(port: number): string {
  return String(port);
}

/** Wildcard binds are reachable over loopback, which is where we probe. */
export function probeAddressFor(address: string): string {
  if (address === '0.0.0.0' || address === '*') return '127.0.0.1';
  if (address === '::') return '::1';
  return address;
}
