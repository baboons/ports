import { readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

/** Chosen to sit well clear of the usual dev-server neighbourhoods. */
export const DEFAULT_PORT = 7373;

export interface ServerConfig {
  port: number;
  /** True when the user named the port, which makes a collision fatal. */
  explicit: boolean;
  host: string;
  open: boolean;
}

export function configPath(): string {
  const xdg = process.env['XDG_CONFIG_HOME'];
  const base = xdg && xdg.trim() !== '' ? xdg : path.join(os.homedir(), '.config');
  return path.join(base, 'ports', 'config.json');
}

async function readConfigFile(): Promise<{ port?: number; host?: string }> {
  try {
    const raw = await readFile(configPath(), 'utf8');
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return {};
    const { port, host } = parsed as { port?: unknown; host?: unknown };
    return {
      ...(isValidPort(port) ? { port } : {}),
      ...(typeof host === 'string' ? { host } : {}),
    };
  } catch {
    return {};
  }
}

export function isValidPort(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= 65535;
}

/**
 * Resolve the port to serve on.
 *
 * Order: --port, then PORTS_PORT, then the config file, then the default.
 * Anything the user stated explicitly is remembered as such so a collision can
 * be reported as an error instead of silently moving somewhere else.
 */
export async function resolveConfig(cliPort?: number, cliHost?: string, open = true): Promise<ServerConfig> {
  if (cliPort !== undefined) {
    return { port: cliPort, explicit: true, host: cliHost ?? '127.0.0.1', open };
  }

  const env = process.env['PORTS_PORT'];
  if (env !== undefined && env.trim() !== '') {
    const parsed = Number.parseInt(env, 10);
    if (!isValidPort(parsed)) {
      throw new Error(`PORTS_PORT is not a valid port: ${env}`);
    }
    return { port: parsed, explicit: true, host: cliHost ?? '127.0.0.1', open };
  }

  const file = await readConfigFile();
  if (file.port !== undefined) {
    return { port: file.port, explicit: true, host: cliHost ?? file.host ?? '127.0.0.1', open };
  }

  return { port: DEFAULT_PORT, explicit: false, host: cliHost ?? '127.0.0.1', open };
}

/** Ports below 1024 need root on macOS and Linux. */
export function isPrivilegedPort(port: number): boolean {
  return port < 1024;
}

export function canBindPrivileged(): boolean {
  return typeof process.getuid !== 'function' || process.getuid() === 0;
}
