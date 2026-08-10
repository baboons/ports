import type { Listener, PortRecord, ScanProgress } from '../shared/types.ts';
import { portId, probeAddressFor } from '../shared/types.ts';
import { enumerateListeners } from './listeners.ts';
import { COMMON_PORTS_UNIQUE } from './common-ports.ts';
import { fullRange, sweepPorts } from './sweep.ts';
import { probePort } from './probe.ts';
import { enrichProcesses } from './process.ts';
import { mergeRecord, markMissing, needsProbe } from './scheduler.ts';
import { cacheFavicon } from '../cache/favicons.ts';

/**
 * How many probe workers run *while the connect sweep is still going*.
 *
 * A handful is plenty: tiers 1 and 2 only ever turn up a dozen or so ports, and
 * this exists so those appear immediately rather than after the sweep. Keeping
 * it small also stops CPU-bound TLS handshakes from competing with the sweep,
 * though on a quiet machine that effect is small enough to sit inside run-to-run
 * noise. The pool scales up once discovery finishes.
 */
const DISCOVERY_PROBE_WORKERS = 4;

export interface ScanOptions {
  /** Run tier 3, the full 1-65535 sweep. On by default. */
  deep?: boolean;
  /** Sockets in flight during the connect sweep. */
  sweepConcurrency?: number;
  /**
   * Parallel HTTP probes once discovery has finished. While the sweep is still
   * running we deliberately use far fewer - see `DISCOVERY_PROBE_WORKERS`.
   */
  probeConcurrency?: number;
  /** Port this process is serving on, so we can flag it rather than hide it. */
  selfPort?: number;
  signal?: AbortSignal;
  /** Fires whenever records are added or change. */
  onRecords?: (records: PortRecord[]) => void;
  onProgress?: (progress: ScanProgress) => void;
  /**
   * What we already knew, from the cache. Ports still inside their TTL keep
   * their cached description instead of being re-probed.
   */
  prior?: Iterable<PortRecord>;
  /** Ignore prior TTLs and re-probe everything found. */
  force?: boolean;
  /** Download and cache favicon bytes for anything serving HTML. */
  fetchFavicons?: boolean;
}

export interface ScanResult {
  /** Everything observed this pass, plus ports confirmed to have gone away. */
  records: PortRecord[];
  /** Whether tier 3 ran to completion, which decides if the sweep TTL resets. */
  sweptFully: boolean;
}

/**
 * Runs the discovery tiers in order of how fast they produce answers, probing
 * each newly found port as soon as it is known rather than waiting for the
 * sweep to finish. Callers get results streamed through `onRecords`.
 */
export async function scan(options: ScanOptions = {}): Promise<ScanResult> {
  const {
    deep = true,
    sweepConcurrency = 512,
    probeConcurrency = 24,
    selfPort,
    signal,
    onRecords,
    onProgress,
    prior,
    force = false,
    fetchFavicons = false,
  } = options;

  const records = new Map<number, PortRecord>();
  const now = () => Date.now();
  const startedAt = now();

  // Everything we knew coming in, keyed by port. Used both to skip probes that
  // are still fresh and to preserve first-seen history through the merge.
  const priorByPort = new Map<number, PortRecord>();
  for (const record of prior ?? []) priorByPort.set(record.port, record);

  /** Ports we actually looked for, so we only mark those absent as dead. */
  const searchedPorts = new Set<number>();

  const progress: ScanProgress = {
    phase: 'lsof',
    scanned: 0,
    total: 0,
    found: 0,
    startedAt,
    done: false,
  };
  const emitProgress = (patch: Partial<ScanProgress> = {}) => {
    Object.assign(progress, patch);
    progress.found = records.size;
    onProgress?.({ ...progress });
  };

  /** Create or update the record for a port without losing known fields. */
  const touch = (
    port: number,
    tier: PortRecord['tier'],
    address: string,
  ): PortRecord => {
    let record = records.get(port);
    if (!record) {
      const cached = priorByPort.get(port);
      record = cached
        ? // Carry the cached description forward so this port is already
          // described if its TTL says it does not need re-probing.
          {
            ...cached,
            tier,
            alive: true,
            stale: true,
            isSelf: selfPort === port,
            lastSeen: now(),
            addresses: [...cached.addresses],
          }
        : {
            id: portId(port),
            port,
            addresses: [],
            probedAddress: probeAddressFor(address),
            alive: true,
            protocol: 'unknown',
            tier,
            stale: false,
            isSelf: selfPort === port,
            firstSeen: now(),
            lastSeen: now(),
            lastProbed: 0,
            consecutiveStable: 0,
          };
      records.set(port, record);
    }
    if (!record.addresses.includes(address)) record.addresses.push(address);
    record.lastSeen = now();
    return record;
  };

  // Ports queued for HTTP probing, drained continuously by the workers below.
  const probeQueue: number[] = [];
  const queued = new Set<number>();
  let discoveryDone = false;

  const enqueue = (port: number) => {
    if (queued.has(port)) return;
    queued.add(port);

    // A port whose cached description is still inside its TTL needs no work:
    // it is already populated by `touch`, so just publish it and move on. This
    // is what keeps a repeat run fast.
    const record = records.get(port);
    if (!force && record && !needsProbe(record)) {
      record.stale = false;
      onRecords?.([record]);
      return;
    }

    probeQueue.push(port);
  };

  /**
   * Probe workers run alongside discovery. They idle-wait while the sweep is
   * still finding ports, and exit once discovery is finished and the queue
   * has drained.
   */
  const probeWorker = async (): Promise<void> => {
    for (;;) {
      if (signal?.aborted) return;
      const port = probeQueue.shift();
      if (port === undefined) {
        if (discoveryDone) return;
        await new Promise((r) => setTimeout(r, 25));
        continue;
      }

      const record = records.get(port);
      if (!record) continue;

      const result = await probePort(port, record.probedAddress, signal);

      const probed: PortRecord = {
        ...record,
        protocol: result.protocol,
        lastProbed: now(),
        probeMs: result.probeMs,
        stale: false,
      };

      const merged = mergeRecord(priorByPort.get(port), probed, now());

      // `mergeRecord` keeps previous values where the new pass saw nothing,
      // which is what we want for process data gathered by a different step.
      // Probe output is different: it is a complete observation, so a server
      // that stopped serving HTML must lose last run's title rather than keep
      // advertising it. Assign these unconditionally, undefined included.
      merged.http = result.http;
      merged.meta = result.meta;
      merged.tls = result.tls;
      merged.error = result.error;

      records.set(port, merged);

      if (fetchFavicons && merged.meta?.faviconUrl) {
        const cachedHash = priorByPort.get(port)?.meta?.faviconHash;
        const sameUrl = priorByPort.get(port)?.meta?.faviconUrl === merged.meta.faviconUrl;
        if (cachedHash && sameUrl) {
          merged.meta.faviconHash = cachedHash;
        } else {
          const hash = await cacheFavicon(merged.meta.faviconUrl, signal);
          if (hash) merged.meta.faviconHash = hash;
        }
      }

      onRecords?.([merged]);
    }
  };

  // Stage one: a light pool that runs alongside discovery so early finds show
  // up straight away without slowing the sweep down.
  const workers = Array.from({ length: DISCOVERY_PROBE_WORKERS }, () => probeWorker());

  // --- Tier 1: the process table. Fast, and the only source of pids. ---
  emitProgress({ phase: 'lsof' });
  let listeners: Listener[] = [];
  try {
    listeners = await enumerateListeners();
  } catch {
    listeners = [];
  }

  for (const listener of listeners) {
    const record = touch(listener.port, 'lsof', listener.address);
    if (listener.pid !== undefined && !record.process) {
      record.process = { pid: listener.pid };
      if (listener.command) record.process.name = listener.command;
      if (listener.user) record.process.user = listener.user;
    }
    enqueue(listener.port);
  }
  if (records.size > 0) onRecords?.([...records.values()]);
  emitProgress();

  // --- Tier 2: the common dev-port list, for anything lsof could not see. ---
  const knownPorts = new Set(records.keys());
  const tier2 = COMMON_PORTS_UNIQUE.filter((p) => !knownPorts.has(p));

  emitProgress({ phase: 'common', scanned: 0, total: tier2.length });
  await sweepPorts(tier2, {
    concurrency: Math.min(sweepConcurrency, 256),
    ...(signal ? { signal } : {}),
    onResult: (port, open) => {
      // Every port here was genuinely tested, so a closed one is evidence.
      searchedPorts.add(port);
      if (!open) return;
      touch(port, 'common', '127.0.0.1');
      enqueue(port);
    },
    onProgress: (scanned, total) => emitProgress({ scanned, total }),
  });
  emitProgress();

  // --- Tier 3: everything else. Slowest, so it runs last and streams. ---
  let sweptFully = false;
  if (deep && !signal?.aborted) {
    const tier3 = fullRange(records.keys());
    emitProgress({ phase: 'sweep', scanned: 0, total: tier3.length });
    await sweepPorts(tier3, {
      concurrency: sweepConcurrency,
      ...(signal ? { signal } : {}),
      onResult: (port, open) => {
        searchedPorts.add(port);
        if (!open) return;
        touch(port, 'sweep', '127.0.0.1');
        enqueue(port);
      },
      onProgress: (scanned, total) => emitProgress({ scanned, total }),
    });
    sweptFully = !signal?.aborted;
  }

  // --- Drain the probe queue. ---
  // Stage two: with no sweep competing for the event loop, scale the pool up
  // to clear whatever tier 3 queued. Matters on machines with many listeners.
  emitProgress({ phase: 'probing' });
  const extra = Math.max(probeConcurrency - DISCOVERY_PROBE_WORKERS, 0);
  const backlogWorkers = Array.from(
    { length: Math.min(extra, probeQueue.length) },
    () => probeWorker(),
  );
  // Set only after the extra workers exist, so they never see an empty queue
  // and exit before the backlog is picked up.
  discoveryDone = true;
  await Promise.all([...workers, ...backlogWorkers]);

  // --- Process enrichment, batched across every pid at once. ---
  const pids = [...records.values()]
    .map((r) => r.process?.pid)
    .filter((p): p is number => typeof p === 'number');

  if (pids.length > 0 && !signal?.aborted) {
    const enriched = await enrichProcesses(pids);
    const changed: PortRecord[] = [];
    for (const record of records.values()) {
      const pid = record.process?.pid;
      if (pid === undefined) continue;
      const info = enriched.get(pid);
      if (!info) continue;
      // lsof's short command name is a reasonable fallback if ps gave nothing.
      record.process = { ...record.process, ...info };
      changed.push(record);
    }
    if (changed.length > 0) onRecords?.(changed);
  }

  // --- Retire ports we looked for and did not find. ---
  // They stay in the result as dead entries rather than vanishing, because the
  // index is meant to remember what used to run where.
  const dead = markMissing(priorByPort.values(), new Set(records.keys()), searchedPorts, now());
  if (dead.length > 0) onRecords?.(dead);

  emitProgress({ phase: 'done', done: true });

  return {
    records: [...records.values(), ...dead].sort((a, b) => a.port - b.port),
    sweptFully,
  };
}
