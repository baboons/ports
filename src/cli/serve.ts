import { execFile } from 'node:child_process';
import http from 'node:http';
import { startServer, HEALTH_SIGNATURE } from '../server/index.ts';
import {
  canBindPrivileged,
  isPrivilegedPort,
  resolveConfig,
} from '../server/config.ts';
import { enumerateListeners } from '../scan/listeners.ts';
import { c } from './format.ts';

/**
 * How the user should re-run us with elevated privileges.
 *
 * argv[1] is the resolved bin path, which is what they actually invoked
 * whether that was a global install, npx, or a source checkout - so the hint
 * stays correct without hardcoding a package name that can change.
 */
function relaunchHint(port: number): string {
  const invoked = process.argv[1] ?? '';
  const viaGlobalBin = /[/\\]ports$/.test(invoked);
  const command = viaGlobalBin ? 'ports' : `node ${invoked}`;
  return `sudo ${command} --port ${port}`;
}

/** Ask a port whether it is another instance of us. */
function identify(port: number, host: string): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.request(
      { host, port, path: '/api/health', method: 'GET', timeout: 700 },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          try {
            const body: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            resolve(
              !!body &&
                typeof body === 'object' &&
                (body as { app?: string }).app === HEALTH_SIGNATURE,
            );
          } catch {
            resolve(false);
          }
        });
      },
    );
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(false));
    req.end();
  });
}

/** Name whatever already holds the port, so the error is actionable. */
async function describeHolder(port: number): Promise<string> {
  try {
    const listeners = await enumerateListeners();
    const match = listeners.find((l) => l.port === port);
    if (!match) return 'another process';
    return match.command
      ? `${match.command}${match.pid ? ` (pid ${match.pid})` : ''}`
      : 'another process';
  } catch {
    return 'another process';
  }
}

function openBrowser(url: string): void {
  const command =
    process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
  try {
    execFile(command, [url], () => {
      // A headless box with no opener is not an error worth reporting.
    });
  } catch {
    // Ditto.
  }
}

export interface ServeArgs {
  port?: number;
  host?: string;
  open: boolean;
  screenshots: boolean;
}

export async function serve(args: ServeArgs): Promise<void> {
  const config = await resolveConfig(args.port, args.host, args.open);

  if (isPrivilegedPort(config.port) && !canBindPrivileged()) {
    process.stderr.write(
      `\n${c.red('Cannot bind port ' + config.port)} — ports below 1024 need root.\n` +
        `  Try:  ${c.bold(relaunchHint(config.port))}\n` +
        `  Or pick an unprivileged port, e.g. ${c.bold('--port 7373')}.\n\n`,
    );
    process.exit(1);
  }

  // If our own instance is already there, hand over to it instead of failing.
  if (await identify(config.port, config.host)) {
    const url = `http://${config.host}:${config.port}/`;
    process.stdout.write(`\n  ports is already running at ${c.bold(url)}\n\n`);
    if (config.open) openBrowser(url);
    return;
  }

  let server;
  try {
    server = await startServer({
      port: config.port,
      host: config.host,
      screenshots: args.screenshots,
    });
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;

    if (code === 'EADDRINUSE') {
      const holder = await describeHolder(config.port);
      if (config.explicit) {
        // The user named this port, so moving elsewhere would be surprising.
        process.stderr.write(
          `\n${c.red('Port ' + config.port + ' is in use')} by ${holder}.\n` +
            `  Choose another port with ${c.bold('--port <n>')}.\n\n`,
        );
        process.exit(1);
      }
      process.stderr.write(
        c.dim(`  Port ${config.port} taken by ${holder}; trying another…\n`),
      );
      server = await startServer({ port: 0, host: config.host, screenshots: args.screenshots });
    } else if (code === 'EACCES') {
      process.stderr.write(
        `\n${c.red('Permission denied binding port ' + config.port)}.\n` +
          `  Try:  ${c.bold(relaunchHint(config.port))}\n\n`,
      );
      process.exit(1);
    } else {
      throw err;
    }
  }

  const address = server.port;
  const url = `http://${config.host === '0.0.0.0' ? 'localhost' : config.host}:${address}/`;

  process.stdout.write(`\n  ${c.bold('ports')} ${c.dim('·')} ${c.cyan(url)}\n`);
  process.stdout.write(c.dim('  scanning in the background — Ctrl-C to stop\n\n'));

  if (config.open) openBrowser(url);

  const shutdown = () => {
    process.stdout.write(c.dim('\n  stopping…\n'));
    void server.close().then(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
