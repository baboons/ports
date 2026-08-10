import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type { ProcessInfo } from '../shared/types.ts';

const exec = promisify(execFile);

/** Manifest files that name a project, in the order we trust them. */
const MANIFESTS: Array<{
  file: string;
  type: NonNullable<ProcessInfo['projectType']>;
  parse: (raw: string) => string | undefined;
}> = [
  { file: 'package.json', type: 'node', parse: parseJsonName },
  { file: 'pyproject.toml', type: 'python', parse: (r) => parseTomlName(r) },
  { file: 'Cargo.toml', type: 'rust', parse: (r) => parseTomlName(r) },
  { file: 'go.mod', type: 'go', parse: parseGoModule },
  { file: 'composer.json', type: 'php', parse: parseJsonName },
  { file: 'Gemfile', type: 'ruby', parse: () => undefined },
];

function parseJsonName(raw: string): string | undefined {
  try {
    const value: unknown = JSON.parse(raw);
    if (value && typeof value === 'object' && 'name' in value) {
      const name = (value as { name?: unknown }).name;
      if (typeof name === 'string' && name.trim()) return name.trim();
    }
  } catch {
    // A malformed manifest is not worth failing enrichment over.
  }
  return undefined;
}

/** Good enough for `name = "x"` under [project], [package] or top level. */
function parseTomlName(raw: string): string | undefined {
  const m = /^\s*name\s*=\s*["']([^"']+)["']/m.exec(raw);
  return m?.[1]?.trim();
}

function parseGoModule(raw: string): string | undefined {
  const m = /^\s*module\s+(\S+)/m.exec(raw);
  const mod = m?.[1];
  // Module paths are URLs; the last segment is the useful label.
  return mod ? (mod.split('/').pop() ?? mod) : undefined;
}

/** Batched `ps` lookup. One spawn for every pid we care about. */
async function readPsInfo(
  pids: number[],
): Promise<Map<number, { user?: string; command?: string }>> {
  const out = new Map<number, { user?: string; command?: string }>();
  if (pids.length === 0) return out;

  try {
    const { stdout } = await exec('ps', ['-o', 'pid=,user=,args=', '-p', pids.join(',')], {
      timeout: 5000,
      maxBuffer: 4 * 1024 * 1024,
    });

    for (const line of stdout.split('\n')) {
      const m = /^\s*(\d+)\s+(\S+)\s+(.*)$/.exec(line);
      if (!m) continue;
      const pid = Number.parseInt(m[1]!, 10);
      const command = m[3]!.trim();
      out.set(pid, {
        ...(m[2] ? { user: m[2] } : {}),
        ...(command ? { command } : {}),
      });
    }
  } catch {
    // ps failing just means less detail in the UI.
  }
  return out;
}

/** Batched cwd lookup. Processes we cannot see simply get no entry. */
async function readCwds(pids: number[]): Promise<Map<number, string>> {
  const out = new Map<number, string>();
  if (pids.length === 0) return out;

  const collect = (stdout: string) => {
    let current: number | undefined;
    for (const line of stdout.split('\n')) {
      if (line.length < 2) continue;
      const tag = line[0]!;
      const value = line.slice(1);
      if (tag === 'p') current = Number.parseInt(value, 10);
      // `/` is every GUI app's cwd and tells us nothing.
      else if (tag === 'n' && current !== undefined && value !== '/') {
        out.set(current, value);
      }
    }
  };

  try {
    const { stdout } = await exec('lsof', ['-a', '-p', pids.join(','), '-d', 'cwd', '-Fpn'], {
      timeout: 5000,
      maxBuffer: 4 * 1024 * 1024,
    });
    collect(stdout);
  } catch (err) {
    const stdout = (err as { stdout?: string }).stdout;
    if (typeof stdout === 'string') collect(stdout);
  }
  return out;
}

/**
 * Just the executable name, stripped of path and arguments.
 *
 * Splitting on the first space would be wrong on macOS, where real binaries
 * live under paths like ".../Application Support/..." and ".../Linear Helper".
 * Instead we cut at the first argument-looking token (" -"), which leaves the
 * full spaced path intact.
 */
function shortName(command: string | undefined): string | undefined {
  if (!command) return undefined;

  // Process titles such as "nginx: worker process" are not paths at all.
  const title = /^([^/:\s]+):\s/.exec(command);
  if (title?.[1]) return title[1];

  const argStart = command.search(/\s-/);
  const executable = (argStart === -1 ? command : command.slice(0, argStart)).trim();

  const base = path.basename(executable);
  return base || undefined;
}

/**
 * Walk up from cwd looking for a project manifest.
 *
 * A dev server is often started from a subdirectory of the repo, so checking
 * only cwd would miss the name. We stop at the filesystem root or after a few
 * levels, whichever comes first.
 */
async function detectProject(
  cwd: string,
): Promise<{ projectName?: string; projectType?: ProcessInfo['projectType'] }> {
  let dir = cwd;
  for (let depth = 0; depth < 5; depth++) {
    for (const manifest of MANIFESTS) {
      try {
        const raw = await readFile(path.join(dir, manifest.file), 'utf8');
        const name = manifest.parse(raw);
        return {
          projectName: name ?? path.basename(dir),
          projectType: manifest.type,
        };
      } catch {
        // Missing manifest, keep looking.
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return {};
}

/**
 * Resolve pids to command, cwd and owning project.
 *
 * Batched deliberately: this runs for every listener on every scan, and
 * spawning two processes per pid would dominate scan time.
 */
export async function enrichProcesses(pids: number[]): Promise<Map<number, ProcessInfo>> {
  const unique = [...new Set(pids)].filter((p) => Number.isInteger(p) && p > 0);
  const result = new Map<number, ProcessInfo>();
  if (unique.length === 0) return result;

  const [psInfo, cwds] = await Promise.all([readPsInfo(unique), readCwds(unique)]);

  await Promise.all(
    unique.map(async (pid) => {
      const ps = psInfo.get(pid);
      const cwd = cwds.get(pid);
      const project = cwd ? await detectProject(cwd) : {};

      const info: ProcessInfo = { pid };
      if (ps?.command) info.command = ps.command;
      if (ps?.user) info.user = ps.user;
      const name = shortName(ps?.command);
      if (name) info.name = name;
      if (cwd) info.cwd = cwd;
      if (project.projectName) info.projectName = project.projectName;
      if (project.projectType) info.projectType = project.projectType;

      result.set(pid, info);
    }),
  );

  return result;
}
