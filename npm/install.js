#!/usr/bin/env node
// Fetch the prebuilt binary for this platform from the GitHub release matching
// this package's version.
//
// `ports` is a Rust program; npm is kept as an install path only because
// @baboons/ports was published there first and people have it in scripts.
// Anyone who would rather not go through npm can `cargo install ports`.
//
// Release artifacts are single gzipped binaries rather than tarballs, so this
// needs nothing but node's own zlib — a package that advertises no runtime
// dependencies should not acquire one in its installer.

import { createWriteStream } from 'node:fs';
import { chmod, mkdir, readFile, rm, stat } from 'node:fs/promises';
import { createGunzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const { version } = JSON.parse(await readFile(path.join(here, 'package.json'), 'utf8'));

const TARGETS = {
  'darwin-arm64': 'aarch64-apple-darwin',
  'darwin-x64': 'x86_64-apple-darwin',
  'linux-arm64': 'aarch64-unknown-linux-gnu',
  'linux-x64': 'x86_64-unknown-linux-gnu',
};

/** Print the fallback and exit successfully. */
function giveUp(reason) {
  console.error(
    `\n  ports: ${reason}\n` + `  Build it instead:  cargo install ports\n`,
  );
  // Deliberately not a failure: `cargo install` is one command away, and a
  // failing postinstall would break an otherwise fine `npm ci`.
  process.exit(0);
}

const key = `${process.platform}-${process.arch}`;
const target = TARGETS[key];
if (!target) giveUp(`no prebuilt binary for ${key}`);

const binDir = path.join(here, 'bin');
const binary = path.join(binDir, 'ports');

// A rebuild or a cached node_modules should not re-download.
try {
  await stat(binary);
  process.exit(0);
} catch {
  // Not there yet, carry on.
}

const url = `https://github.com/baboons/ports/releases/download/v${version}/ports-${target}.gz`;

try {
  const response = await fetch(url, { redirect: 'follow' });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }

  await mkdir(binDir, { recursive: true });
  await pipeline(
    Readable.fromWeb(response.body),
    createGunzip(),
    createWriteStream(binary),
  );
  await chmod(binary, 0o755);
} catch (err) {
  // Half a binary is worse than none: it would run and fail confusingly.
  await rm(binDir, { recursive: true, force: true });
  giveUp(`could not download ${version} for ${target} — ${err.message}`);
}
