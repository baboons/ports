import type { PortRecord } from '../shared/types.ts';

/** ANSI helpers that no-op when the stream is not a TTY or NO_COLOR is set. */
const enabled =
  process.stdout.isTTY === true && !process.env['NO_COLOR'] && process.env['TERM'] !== 'dumb';

const wrap = (open: number, close: number) => (s: string) =>
  enabled ? `[${open}m${s}[${close}m` : s;

export const c = {
  bold: wrap(1, 22),
  dim: wrap(2, 22),
  red: wrap(31, 39),
  green: wrap(32, 39),
  yellow: wrap(33, 39),
  blue: wrap(34, 39),
  magenta: wrap(35, 39),
  cyan: wrap(36, 39),
  gray: wrap(90, 39),
};

/** Visible width, ignoring ANSI escapes so padding stays correct. */
export function width(s: string): number {
  return s.replace(/\[\d+m/g, '').length;
}

function pad(s: string, to: number): string {
  const diff = to - width(s);
  return diff > 0 ? s + ' '.repeat(diff) : s;
}

function truncate(s: string, max: number): string {
  if (max <= 1) return '';
  return width(s) <= max ? s : `${s.slice(0, max - 1)}…`;
}

function statusColor(status: number): (s: string) => string {
  if (status >= 500) return c.red;
  if (status >= 400) return c.yellow;
  if (status >= 300) return c.cyan;
  if (status >= 200) return c.green;
  return c.gray;
}

function protocolLabel(record: PortRecord): string {
  // Remembered-but-unverified rows are dimmed uniformly, so the colour tells
  // you how much to trust the row before you read it.
  if (record.stale) return c.gray(record.protocol === 'unknown' ? '?' : record.protocol);

  switch (record.protocol) {
    case 'https':
      return c.green('https');
    case 'http':
      return c.blue('http');
    case 'tcp':
      return c.gray('tcp');
    default:
      return c.gray('?');
  }
}

/** Best human label for a record: page title, else project, else process. */
export function labelFor(record: PortRecord): string {
  return (
    record.meta?.title ??
    record.process?.projectName ??
    record.process?.name ??
    (record.protocol === 'tcp' ? '(non-http service)' : '(no title)')
  );
}

export interface TableOptions {
  /** Include ports that never answered HTTP. */
  includeTcp?: boolean;
  maxWidth?: number;
}

export function renderTable(records: PortRecord[], options: TableOptions = {}): string {
  const { includeTcp = false, maxWidth = process.stdout.columns ?? 120 } = options;

  const web = records.filter((r) => r.protocol === 'http' || r.protocol === 'https');
  const other = records.filter((r) => r.protocol !== 'http' && r.protocol !== 'https');

  const lines: string[] = [];

  if (web.length === 0) {
    lines.push(c.dim('  No HTTP servers found.'));
  } else {
    lines.push(...renderRows(web, maxWidth));
  }

  if (other.length > 0) {
    lines.push('');
    if (includeTcp) {
      lines.push(c.dim(`  Other listeners (${other.length})`));
      lines.push(...renderRows(other, maxWidth));
    } else {
      const ports = other.map((r) => r.port).join(', ');
      lines.push(
        c.dim(
          `  ${other.length} non-HTTP listener${other.length === 1 ? '' : 's'}: ${truncate(ports, Math.max(maxWidth - 30, 20))}  ${c.gray('(--all to show)')}`,
        ),
      );
    }
  }

  return lines.join('\n');
}

function renderRows(records: PortRecord[], maxWidth: number): string[] {
  const rows = records.map((record) => {
    const status = record.http?.status;
    const statusCell =
      status === undefined ? c.gray('—') : statusColor(status)(String(status));

    const project = record.process?.projectName;
    const proc = record.process?.name;
    // Prefer the project name; fall back to the binary, and show both only
    // when they add different information.
    let source =
      project && proc && project !== proc
        ? `${project} ${c.gray(`(${proc})`)}`
        : (project ?? proc ?? '');

    // A port with no page title falls back to the process name, which would
    // otherwise print the same string twice across two columns.
    const title = labelFor(record);
    if (source === title) source = '';

    return {
      port: c.bold(String(record.port)),
      protocol: protocolLabel(record),
      status: statusCell,
      title,
      source,
      extra: record.http?.framework ?? record.http?.server ?? '',
    };
  });

  const w = {
    port: Math.max(...rows.map((r) => width(r.port)), 4),
    protocol: Math.max(...rows.map((r) => width(r.protocol)), 5),
    status: Math.max(...rows.map((r) => width(r.status)), 3),
    source: Math.min(Math.max(...rows.map((r) => width(r.source)), 0), 28),
    extra: Math.min(Math.max(...rows.map((r) => width(r.extra)), 0), 14),
  };

  // Whatever is left after the fixed columns goes to the title.
  const fixed = w.port + w.protocol + w.status + w.source + w.extra + 12;
  const titleWidth = Math.max(maxWidth - fixed, 16);

  return rows.map((r) => {
    const cells = [
      pad(r.port, w.port),
      pad(r.protocol, w.protocol),
      pad(r.status, w.status),
      pad(truncate(r.title, titleWidth), titleWidth),
      pad(c.gray(truncate(r.source, w.source)), w.source),
      c.dim(truncate(r.extra, w.extra)),
    ];
    return `  ${cells.join('  ')}`.trimEnd();
  });
}
