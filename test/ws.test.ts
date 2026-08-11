import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { CdpSocket } from '../src/scan/ws.ts';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

/** Server-side framing: unmasked, per RFC 6455. */
function frame(payload: Buffer, opcode = 0x1): Buffer {
  const length = payload.length;
  let header: Buffer;

  if (length < 126) {
    header = Buffer.alloc(2);
    header[1] = length;
  } else if (length < 65536) {
    header = Buffer.alloc(4);
    header[1] = 126;
    header.writeUInt16BE(length, 2);
  } else {
    header = Buffer.alloc(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(length), 2);
  }
  header[0] = 0x80 | opcode;
  return Buffer.concat([header, payload]);
}

/**
 * A WebSocket echo server just complete enough to test the client against:
 * real handshake, real masked-frame parsing, real framing on the way back.
 */
function echoServer(): Promise<{ url: string; close: () => void }> {
  const server = http.createServer();

  server.on('upgrade', (req, socket) => {
    const key = req.headers['sec-websocket-key'] as string;
    const accept = createHash('sha1').update(key + GUID).digest('base64');
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );

    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);

      for (;;) {
        if (buffer.length < 2) return;
        const opcode = buffer[0]! & 0x0f;
        const masked = (buffer[1]! & 0x80) !== 0;
        let length = buffer[1]! & 0x7f;
        let offset = 2;

        if (length === 126) {
          if (buffer.length < 4) return;
          length = buffer.readUInt16BE(2);
          offset = 4;
        } else if (length === 127) {
          if (buffer.length < 10) return;
          length = Number(buffer.readBigUInt64BE(2));
          offset = 10;
        }

        // Clients MUST mask; verifying that is part of the point of this test.
        assert.equal(masked, true, 'client frames must be masked');
        const mask = buffer.subarray(offset, offset + 4);
        offset += 4;
        if (buffer.length < offset + length) return;

        const payload = Buffer.allocUnsafe(length);
        for (let i = 0; i < length; i++) {
          payload[i] = buffer[offset + i]! ^ mask[i % 4]!;
        }
        buffer = buffer.subarray(offset + length);

        if (opcode === 0x8) {
          socket.end();
          return;
        }
        socket.write(frame(payload));
      }
    });
    socket.on('error', () => socket.destroy());
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        url: `ws://127.0.0.1:${port}/`,
        close: () => server.close(),
      });
    });
  });
}

async function roundTrip(payloads: string[]): Promise<string[]> {
  const { url, close } = await echoServer();
  const ws = new CdpSocket();
  const received: string[] = [];

  const done = new Promise<void>((resolve) => {
    ws.on({
      onMessage: (data) => {
        received.push(data);
        if (received.length === payloads.length) resolve();
      },
    });
  });

  await ws.connect(url);
  for (const payload of payloads) ws.send(payload);
  await done;

  ws.close();
  close();
  return received;
}

test('round-trips a short message', async () => {
  const [got] = await roundTrip(['{"id":1,"method":"Page.enable"}']);
  assert.equal(got, '{"id":1,"method":"Page.enable"}');
});

test('handles every payload-length encoding', async () => {
  // 125 is the last 7-bit length, 126 switches to a 16-bit length, and
  // anything past 65535 switches again to 64-bit. CDP screenshots live in
  // that last bucket, so all three must work.
  const sizes = [125, 126, 1000, 65535, 65536, 400_000];
  const payloads = sizes.map((n) => 'x'.repeat(n));

  const got = await roundTrip(payloads);
  assert.deepEqual(
    got.map((s) => s.length),
    sizes,
  );
});

test('reassembles a payload split across many TCP chunks', async () => {
  // A 400KB frame never arrives in one read; this is the path that matters
  // for screenshots, where the base64 image spans dozens of packets.
  const payload = JSON.stringify({ id: 7, result: { data: 'a'.repeat(500_000) } });
  const [got] = await roundTrip([payload]);
  assert.equal(got, payload);
});

test('preserves multi-byte utf-8 across frames', async () => {
  const payload = JSON.stringify({ title: 'café — 日本語 — 🎛️'.repeat(100) });
  const [got] = await roundTrip([payload]);
  assert.equal(got, payload);
});

test('reports a refused upgrade instead of hanging', async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const { port } = server.address() as AddressInfo;

  const ws = new CdpSocket();
  await assert.rejects(() => ws.connect(`ws://127.0.0.1:${port}/`), /refused/);
  server.close();
});
