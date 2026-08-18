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

import { createHash } from 'node:crypto';
import { chmod, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const { version } = JSON.parse(await readFile(path.join(here, 'package.json'), 'utf8'));

// Only what CI actually publishes. Listing more would turn an unsupported
// platform into a confusing 404 instead of a clear "build it yourself".
const TARGETS = {
  'darwin-arm64': 'aarch64-apple-darwin',
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

const base = `https://github.com/baboons/ports/releases/download/v${version}`;
const artifact = `ports-${target}.gz`;

async function get(url) {
  const response = await fetch(url, { redirect: 'follow' });
  if (!response.ok) {
    throw new Error(`${url} — ${response.status} ${response.statusText}`);
  }
  return Buffer.from(await response.arrayBuffer());
}

try {
  // Verified before anything is written, so a truncated or corrupted download
  // never reaches disk as an executable.
  const manifest = (await get(`${base}/checksums.txt`)).toString('utf8');
  const line = manifest
    .split('\n')
    .map((l) => l.trim().split(/\s+/))
    .find(([, name]) => name?.replace(/^\*/, '') === artifact);

  if (!line) throw new Error(`release has no checksum for ${artifact}`);
  const expected = line[0].toLowerCase();

  const compressed = await get(`${base}/${artifact}`);
  const actual = createHash('sha256').update(compressed).digest('hex');
  if (actual !== expected) {
    throw new Error(`checksum mismatch — expected ${expected}, got ${actual}`);
  }

  await mkdir(binDir, { recursive: true });
  await writeFile(binary, gunzipSync(compressed));
  await chmod(binary, 0o755);
} catch (err) {
  // Half a binary is worse than none: it would run and fail confusingly.
  await rm(binDir, { recursive: true, force: true });
  giveUp(`could not install ${version} for ${target} — ${err.message}`);
}
