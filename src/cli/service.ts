import { execFile } from 'node:child_process';
import { mkdir, readFile, unlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { c } from './format.ts';

const exec = promisify(execFile);

export type ServiceAction = 'install' | 'uninstall' | 'status' | 'print';

export interface ServiceArgs {
  action: ServiceAction;
  /** Install for the current user instead of system-wide. */
  user: boolean;
  port?: number;
  host?: string;
  screenshots: boolean;
}

const SERVICE_NAME = 'ports';
const LAUNCHD_LABEL = 'dev.baboons.ports';

function isRoot(): boolean {
  return typeof process.getuid === 'function' && process.getuid() === 0;
}

/**
 * The exact command a service manager should run.
 *
 * Resolved from the live process rather than guessed, so it keeps working
 * whether ports was installed globally, run through npx, or is a source
 * checkout being driven by `node --experimental-strip-types`.
 */
function execCommand(args: ServiceArgs): string[] {
  const node = process.execPath;
  const script = process.argv[1];
  if (!script) throw new Error('cannot determine the ports executable path');

  const flags = ['--no-open'];
  if (args.port !== undefined) flags.push('--port', String(args.port));
  if (args.host !== undefined) flags.push('--host', args.host);
  if (!args.screenshots) flags.push('--no-screenshots');

  // Running a .ts entry point needs the stripper; a built dist/cli.js does not.
  const needsStrip = script.endsWith('.ts');
  return needsStrip
    ? [node, '--experimental-strip-types', script, ...flags]
    : [node, script, ...flags];
}

function quote(parts: string[]): string {
  return parts.map((p) => (/[\s"']/.test(p) ? JSON.stringify(p) : p)).join(' ');
}

// --- systemd ---------------------------------------------------------------

function systemdPath(user: boolean): string {
  return user
    ? path.join(os.homedir(), '.config', 'systemd', 'user', `${SERVICE_NAME}.service`)
    : `/etc/systemd/system/${SERVICE_NAME}.service`;
}

function systemdUnit(args: ServiceArgs): string {
  const command = quote(execCommand(args));

  // A system unit runs as root deliberately. Falling back to SUDO_USER would
  // be worse than it looks: the service could no longer bind a privileged port
  // (the main reason to install system-wide), and unprivileged lsof would only
  // see that one user's processes. A --user unit already runs as its owner, so
  // it needs no User= at all.
  //
  // HOME is likewise omitted: systemd derives it from User=, whereas copying
  // os.homedir() here would bake in whatever HOME sudo happened to leave set.
  const runAs = args.user ? '' : 'User=root\n';

  return `[Unit]
Description=ports — localhost HTTP server dashboard
Documentation=https://github.com/baboons/ports
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${command}
${runAs}Restart=on-failure
RestartSec=5
# The scanner opens thousands of short-lived sockets during a full sweep.
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=${args.user ? 'default.target' : 'multi-user.target'}
`;
}

async function systemctl(args: ServiceArgs, ...command: string[]): Promise<string> {
  const scope = args.user ? ['--user'] : [];
  const { stdout, stderr } = await exec('systemctl', [...scope, ...command], { timeout: 20_000 });
  return `${stdout}${stderr}`.trim();
}

// --- launchd ---------------------------------------------------------------

function launchdPath(): string {
  return path.join(os.homedir(), 'Library', 'LaunchAgents', `${LAUNCHD_LABEL}.plist`);
}

function launchdPlist(args: ServiceArgs): string {
  const command = execCommand(args);
  const entries = command.map((part) => `      <string>${escapeXml(part)}</string>`).join('\n');
  const logDir = path.join(os.homedir(), 'Library', 'Logs');

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>${LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
${entries}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
      <key>SuccessfulExit</key>
      <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>${logDir}/${SERVICE_NAME}.log</string>
    <key>StandardErrorPath</key>
    <string>${logDir}/${SERVICE_NAME}.error.log</string>
  </dict>
</plist>
`;
}

function escapeXml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// --- Entry point -----------------------------------------------------------

export async function service(args: ServiceArgs): Promise<void> {
  const linux = process.platform === 'linux';
  const mac = process.platform === 'darwin';

  if (!linux && !mac) {
    process.stderr.write(
      `\n${c.red('Unsupported platform')} — service install covers Linux (systemd) and macOS (launchd).\n\n`,
    );
    process.exit(1);
  }

  const unit = linux ? systemdUnit(args) : launchdPlist(args);
  const target = linux ? systemdPath(args.user) : launchdPath();

  if (args.action === 'print') {
    process.stdout.write(`${c.dim(`# ${target}`)}\n${unit}`);
    return;
  }

  // A system-wide systemd unit lives under /etc; without root the write fails
  // with a bare EACCES, which is a poor way to learn you needed sudo.
  if (linux && !args.user && !isRoot()) {
    process.stderr.write(
      `\n${c.red('Root required')} to manage a system service.\n` +
        `  Try:  ${c.bold(`sudo ${quote([process.argv[1] ?? 'ports', 'service', args.action])}`)}\n` +
        `  Or install just for you: ${c.bold('ports service ' + args.action + ' --user')}\n\n`,
    );
    process.exit(1);
  }

  if (args.action === 'install') {
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, unit, 'utf8');
    process.stdout.write(`\n  wrote ${c.bold(target)}\n`);

    if (linux) {
      await systemctl(args, 'daemon-reload');
      await systemctl(args, 'enable', SERVICE_NAME);
      await systemctl(args, 'restart', SERVICE_NAME);
      process.stdout.write(`  enabled and started ${c.bold(SERVICE_NAME)}\n`);

      if (args.user) {
        // A --user unit only survives logout once lingering is on; without
        // this the "starts at boot" expectation quietly fails.
        process.stdout.write(
          c.yellow(
            `  note: user services stop at logout unless you run ` +
              `'sudo loginctl enable-linger ${os.userInfo().username}'\n`,
          ),
        );
      }

      process.stdout.write(
        c.dim(
          `  logs:   journalctl ${args.user ? '--user ' : ''}-u ${SERVICE_NAME} -f\n` +
            `  status: ports service status${args.user ? ' --user' : ''}\n\n`,
        ),
      );
    } else {
      // bootstrap replaced `load` in modern launchd; fall back for old macOS.
      const domain = `gui/${process.getuid?.() ?? 501}`;
      try {
        await exec('launchctl', ['bootout', domain, target]).catch(() => undefined);
        await exec('launchctl', ['bootstrap', domain, target]);
      } catch {
        await exec('launchctl', ['load', '-w', target]);
      }
      process.stdout.write(`  loaded ${c.bold(LAUNCHD_LABEL)}\n`);
      process.stdout.write(
        c.dim(`  logs: tail -f ~/Library/Logs/${SERVICE_NAME}.log\n\n`),
      );
    }
    return;
  }

  if (args.action === 'uninstall') {
    if (linux) {
      await systemctl(args, 'disable', '--now', SERVICE_NAME).catch(() => undefined);
    } else {
      const domain = `gui/${process.getuid?.() ?? 501}`;
      await exec('launchctl', ['bootout', domain, target]).catch(() =>
        exec('launchctl', ['unload', '-w', target]).catch(() => undefined),
      );
    }

    try {
      await unlink(target);
      process.stdout.write(`\n  removed ${c.bold(target)}\n\n`);
    } catch {
      process.stdout.write(`\n  nothing installed at ${c.dim(target)}\n\n`);
    }

    if (linux) await systemctl(args, 'daemon-reload').catch(() => undefined);
    return;
  }

  // status
  try {
    await readFile(target, 'utf8');
  } catch {
    process.stdout.write(`\n  not installed ${c.dim(`(${target})`)}\n\n`);
    return;
  }

  if (linux) {
    const output = await systemctl(args, 'status', SERVICE_NAME, '--no-pager').catch(
      (err: { stdout?: string; stderr?: string }) =>
        `${err.stdout ?? ''}${err.stderr ?? ''}`.trim() || 'inactive',
    );
    process.stdout.write(`\n${output}\n\n`);
  } else {
    const { stdout } = await exec('launchctl', ['list']).catch(() => ({ stdout: '' }));
    const line = stdout.split('\n').find((l) => l.includes(LAUNCHD_LABEL));
    process.stdout.write(
      `\n  ${line ? c.green('running') : c.yellow('installed but not running')} ${c.dim(`(${target})`)}\n\n`,
    );
  }
}
