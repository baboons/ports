import test from 'node:test';
import assert from 'node:assert/strict';
import { parseLsof } from '../src/scan/listeners.ts';
import { detectFramework, extractMeta, rankFavicons } from '../src/scan/metadata.ts';

test('parseLsof collapses a process holding one address on many descriptors', () => {
  // nginx forks ten workers that all share the same listening socket.
  const output = ['p553', 'cnginx', 'Ljohan', 'f6', 'tIPv4', 'n127.0.0.1:80']
    .concat(['p554', 'cnginx', 'Ljohan', 'f6', 'tIPv4', 'n127.0.0.1:80'])
    .concat(['p555', 'cnginx', 'Ljohan', 'f6', 'tIPv4', 'n127.0.0.1:80'])
    .join('\n');

  const listeners = parseLsof(output);
  assert.equal(listeners.length, 1);
  assert.equal(listeners[0]?.port, 80);
  assert.equal(listeners[0]?.command, 'nginx');
  assert.equal(listeners[0]?.pid, 553);
});

test('parseLsof keeps ipv4 and ipv6 binds of the same port distinct', () => {
  const output = [
    'p56373',
    'cnode',
    'f15',
    'tIPv4',
    'n127.0.0.1:18789',
    'f16',
    'tIPv6',
    'n[::1]:18789',
  ].join('\n');

  const listeners = parseLsof(output);
  assert.equal(listeners.length, 2);
  assert.deepEqual(
    listeners.map((l) => [l.address, l.family]),
    [
      ['127.0.0.1', 'ipv4'],
      ['::1', 'ipv6'],
    ],
  );
});

test('parseLsof normalises a wildcard bind', () => {
  const listeners = parseLsof(['p713', 'crapportd', 'f14', 'tIPv4', 'n*:52259'].join('\n'));
  assert.equal(listeners[0]?.address, '0.0.0.0');
  assert.equal(listeners[0]?.port, 52259);
});

test('parseLsof ignores malformed and out-of-range addresses', () => {
  const output = ['p1', 'cx', 'nnot-an-address', 'n127.0.0.1:99999', 'n127.0.0.1:0'].join('\n');
  assert.deepEqual(parseLsof(output), []);
});

test('extractMeta pulls title, description and theme colour', () => {
  const html = `<html><head>
    <title>  Ports   Test  </title>
    <meta name="description" content="Scans &amp; indexes local servers">
    <meta name="theme-color" content="#ff6600">
  </head></html>`;

  const meta = extractMeta(html, 'http://127.0.0.1:3000/');
  // Whitespace collapsed, entities decoded.
  assert.equal(meta.title, 'Ports Test');
  assert.equal(meta.description, 'Scans & indexes local servers');
  assert.equal(meta.themeColor, '#ff6600');
});

test('extractMeta falls back to og: tags when the basics are missing', () => {
  const html = `<head>
    <meta property="og:title" content="From OpenGraph">
    <meta property="og:description" content="Fallback description">
  </head>`;

  const meta = extractMeta(html, 'http://127.0.0.1:3000/');
  assert.equal(meta.title, 'From OpenGraph');
  assert.equal(meta.description, 'Fallback description');
});

test('extractMeta defaults to /favicon.ico when no icon is declared', () => {
  const meta = extractMeta('<head><title>x</title></head>', 'http://127.0.0.1:8080/app/');
  assert.equal(meta.faviconUrl, 'http://127.0.0.1:8080/favicon.ico');
});

test('rankFavicons prefers svg, then the largest declared raster', () => {
  const html = `<head>
    <link rel="icon" href="/small.png" sizes="16x16">
    <link rel="icon" href="/big.png" sizes="180x180">
    <link rel="icon" type="image/svg+xml" href="/vector.svg">
  </head>`;

  const ranked = rankFavicons(html, 'http://127.0.0.1:3000/');
  assert.equal(ranked[0]?.href, 'http://127.0.0.1:3000/vector.svg');
  assert.equal(ranked[1]?.href, 'http://127.0.0.1:3000/big.png');
});

test('rankFavicons resolves relative hrefs against the page URL', () => {
  const html = '<link rel="icon" href="assets/icon.png">';
  const ranked = rankFavicons(html, 'http://127.0.0.1:3000/dash/');
  assert.equal(ranked[0]?.href, 'http://127.0.0.1:3000/dash/assets/icon.png');
});

test('rankFavicons handles single quotes and unquoted attributes', () => {
  const ranked = rankFavicons("<link rel='icon' href=/a.png>", 'http://127.0.0.1:1/');
  assert.equal(ranked[0]?.href, 'http://127.0.0.1:1/a.png');
});

test('detectFramework reads fingerprint headers ahead of the server header', () => {
  assert.equal(detectFramework({ 'x-nextjs-cache': 'HIT', server: 'nginx' }), 'Next.js');
  assert.equal(detectFramework({ 'x-powered-by': 'Express' }), 'Express');
  assert.equal(detectFramework({ server: 'uvicorn' }), 'Uvicorn');
  assert.equal(detectFramework({ server: 'Werkzeug/3.0.1 Python/3.12' }), 'Flask');
  assert.equal(detectFramework({}), undefined);
});
