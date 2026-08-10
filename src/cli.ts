#!/usr/bin/env node
import { scan } from './scan/scanner.ts';
import { isPrivileged } from './scan/listeners.ts';
import { isSweepDue } from './scan/scheduler.ts';
import { loadCache, saveCache } from './cache/store.ts';
import { c, renderTable } from './cli/format.ts';
import { serve } from './cli/serve.ts';
import type { PortRecord, ScanProgress } from './shared/types.ts';

interface Args {
  command: 'serve' | 'ls' | 'help';
  json: boolean;
  all: boolean;
  fast: boolean;
  quiet: boolean;
  refresh: boolean;
  noCache: boolean;
  screenshots: boolean;
  port?: number;
  host?: string;
  open: boolean;
}

function parseArgs(argv: string[]): Args {
  // No subcommand means run the UI; `ls` is the one-shot terminal view.
  const args: Args = {
    command: 'serve',
    json: false,
    all: false,
    fast: false,
    quiet: false,
    refresh: false,
    noCache: false,
    screenshots: true,
    open: true,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;

    // Options that take a value, in both `--port 80` and `--port=80` forms.
    const valued = /^--(port|host)(=(.*))?$/.exec(arg);
    if (valued) {
      const name = valued[1]!;
      const inline = valued[3];
      const raw = inline !== undefined ? inline : argv[++i];
      if (raw === undefined || raw === '') {
        process.stderr.write(`Missing value for --${name}\n`);
        process.exit(2);
      }
      if (name === 'port') {
        const port = Number.parseInt(raw, 10);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
          process.stderr.write(`Invalid port: ${raw}\n`);
          process.exit(2);
        }
        args.port = port;
      } else {
        args.host = raw;
      }
      continue;
    }

    switch (arg) {
      case 'serve':
      case 'ui':
        args.command = 'serve';
        break;
      case 'ls':
        args.command = 'ls';
        break;
      case '--no-open':
        args.open = false;
        break;
      case '--no-screenshots':
        args.screenshots = false;
        break;
      case '--json':
        args.json = true;
        break;
      case '--all':
      case '-a':
        args.all = true;
        break;
      case '--fast':
        args.fast = true;
        break;
      case '--quiet':
      case '-q':
        args.quiet = true;
        break;
      case '--refresh':
      case '-r':
        args.refresh = true;
        break;
      case '--no-cache':
        args.noCache = true;
        break;
      case '--help':
      case '-h':
        args.command = 'help';
        break;
      default:
        if (arg.startsWith('-')) {
          process.stderr.write(`Unknown option: ${arg}\n`);
          process.exit(2);
        }
    }
  }

  return args;
}

const HELP = `
${c.bold('ports')} — find the HTTP servers running on this machine

${c.bold('Usage')}
  ports                  Serve the live web UI and open it
  ports ls               Print a one-shot table instead

${c.bold('Server options')}
      --port <n>   Port to serve the UI on (default 7373)
      --host <h>   Interface to bind (default 127.0.0.1)
      --no-open    Do not open a browser
      --no-screenshots  Skip page thumbnails (no headless browser)

${c.bold('Listing options')}
  -a, --all        Include listeners that do not speak HTTP
      --fast       Skip the full 1-65535 sweep (tiers 0-2 only)
  -r, --refresh    Ignore cached descriptions and re-probe everything
      --no-cache   Do not read or write the cache at all
      --json       Emit JSON instead of a table
  -q, --quiet      Suppress the progress line
  -h, --help       Show this help

${c.bold('Examples')}
  ports --port 8080
  sudo ports --port 80
  ports ls --json | jq '.[] | select(.protocol=="https")'
`;

/** A single rewritten status line, so progress does not scroll the terminal. */
function createProgressLine(): {
  update: (p: ScanProgress) => void;
  clear: () => void;
} {
  const isTty = process.stderr.isTTY === true;
  let last = 0;

  const update = (p: ScanProgress) => {
    if (!isTty || p.done) return;
    // The sweep fires thousands of updates; repaint at most every 80ms.
    const now = Date.now();
    if (now - last < 80) return;
    last = now;

    const phase =
      p.phase === 'lsof'
        ? 'reading process table'
        : p.phase === 'common'
          ? 'checking common ports'
          : p.phase === 'sweep'
            ? 'sweeping all ports'
            : p.phase === 'probing'
              ? 'probing services'
              : p.phase;

    const pct = p.total > 0 ? ` ${Math.floor((p.scanned / p.total) * 100)}%` : '';
    process.stderr.write(`\r${c.dim(`  ${phase}${pct} — ${p.found} found`)}[K`);
  };

  const clear = () => {
    if (isTty) process.stderr.write('\r[K');
  };

  return { update, clear };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (args.command === 'help') {
    process.stdout.write(`${HELP}\n`);
    return;
  }

  if (args.command === 'serve') {
    await serve({
      ...(args.port !== undefined ? { port: args.port } : {}),
      ...(args.host !== undefined ? { host: args.host } : {}),
      open: args.open,
      screenshots: args.screenshots,
    });
    return;
  }

  const controller = new AbortController();
  const onSigint = () => {
    controller.abort();
    process.stderr.write('\n');
    process.exit(130);
  };
  process.on('SIGINT', onSigint);

  const progress = args.quiet || args.json ? null : createProgressLine();
  const started = Date.now();

  const cache = args.noCache ? null : await loadCache();

  // The full sweep is the expensive tier by an order of magnitude. If one
  // completed recently, tiers 1 and 2 are enough to keep the picture current,
  // which is what makes a repeat run return in under a second.
  const sweepDue = args.refresh || !cache || isSweepDue(cache.lastFullSweep);
  const deep = !args.fast && sweepDue;

  let records: PortRecord[];
  let sweptFully = false;
  try {
    const result = await scan({
      deep,
      force: args.refresh,
      fetchFavicons: true,
      signal: controller.signal,
      ...(cache ? { prior: cache.records } : {}),
      ...(progress ? { onProgress: progress.update } : {}),
    });
    records = result.records;
    sweptFully = result.sweptFully;
  } finally {
    progress?.clear();
  }

  // Fold this pass into the index. Ports we did not look at this time keep
  // their last known state: skipping the sweep must make the answer cheaper,
  // never smaller. Anything carried over is flagged stale so it reads as
  // remembered rather than observed.
  const index = new Map<number, PortRecord>();
  const observed = new Set(records.map((r) => r.port));
  for (const cached of cache?.records ?? []) {
    if (observed.has(cached.port)) continue;
    index.set(cached.port, { ...cached, stale: true });
  }
  for (const record of records) index.set(record.port, record);

  const merged = [...index.values()].sort((a, b) => a.port - b.port);

  if (cache) {
    await saveCache({
      ...cache,
      lastFullSweep: sweptFully ? Date.now() : cache.lastFullSweep,
      records: merged,
    });
  }

  if (args.json) {
    process.stdout.write(`${JSON.stringify(merged, null, 2)}\n`);
    return;
  }

  // Dead entries are kept in the cache for the index, but `ls` is a view of
  // what is running right now.
  const live = merged.filter((r) => r.alive);
  const web = live.filter((r) => r.protocol === 'http' || r.protocol === 'https');
  const elapsed = ((Date.now() - started) / 1000).toFixed(1);

  process.stdout.write('\n');
  process.stdout.write(renderTable(live, { includeTcp: args.all }));
  process.stdout.write('\n\n');

  const parts = [
    `${web.length} web server${web.length === 1 ? '' : 's'}`,
    `${live.length} listener${live.length === 1 ? '' : 's'}`,
    `${elapsed}s`,
  ];
  if (!deep && !args.fast) {
    // Be explicit that coverage was narrowed, rather than quietly showing less.
    parts.push('cached sweep');
  }
  process.stdout.write(c.dim(`  ${parts.join(' · ')}`));
  process.stdout.write('\n');

  if (!deep && !args.fast) {
    process.stdout.write(
      c.gray('  Full port sweep skipped; still fresh. Use --refresh to force one.\n'),
    );
  }
  if (!isPrivileged()) {
    process.stdout.write(c.gray('  Run with sudo to see other users’ processes.\n'));
  }
  process.stdout.write('\n');
}

main().catch((err: unknown) => {
  process.stderr.write(`\n${c.red('ports failed:')} ${String(err)}\n`);
  process.exit(1);
});
