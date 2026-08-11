import { randomBytes } from 'node:crypto';
import http from 'node:http';
import type { Socket } from 'node:net';

/**
 * A minimal RFC 6455 client, just large enough to speak CDP over loopback.
 *
 * Node only exposes a global `WebSocket` from 22.4 onwards, and this package
 * supports Node 20. Rather than making screenshots quietly unavailable on the
 * older runtime - which is exactly what a NAS or a Debian box tends to have -
 * we bring our own. The surface needed is small: one unencrypted connection to
 * 127.0.0.1, text frames, no extensions, no subprotocols.
 *
 * This is used on every runtime, not just old ones, so it is exercised
 * constantly rather than being a fallback that only runs where nobody looks.
 */

const OPCODE = {
  continuation: 0x0,
  text: 0x1,
  binary: 0x2,
  close: 0x8,
  ping: 0x9,
  pong: 0xa,
} as const;

export interface WsHandlers {
  onMessage?: (data: string) => void;
  onClose?: () => void;
  onError?: (err: Error) => void;
}

export class CdpSocket {
  #socket: Socket | undefined;
  #buffer: Buffer = Buffer.alloc(0);
  /** Payloads of a fragmented message, awaiting its FIN frame. */
  #fragments: Buffer[] = [];
  #fragmentOpcode = 0;
  #handlers: WsHandlers = {};
  #closed = false;

  get connected(): boolean {
    return !this.#closed && this.#socket !== undefined && !this.#socket.destroyed;
  }

  on(handlers: WsHandlers): void {
    this.#handlers = { ...this.#handlers, ...handlers };
  }

  /** Perform the upgrade handshake and take ownership of the raw socket. */
  connect(url: string, timeoutMs = 10_000): Promise<void> {
    return new Promise((resolve, reject) => {
      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch {
        return reject(new Error(`invalid websocket url: ${url}`));
      }

      const key = randomBytes(16).toString('base64');
      const req = http.request({
        hostname: parsed.hostname,
        port: parsed.port || 80,
        path: `${parsed.pathname}${parsed.search}`,
        method: 'GET',
        headers: {
          Connection: 'Upgrade',
          Upgrade: 'websocket',
          'Sec-WebSocket-Key': key,
          'Sec-WebSocket-Version': '13',
        },
      });

      const timer = setTimeout(() => {
        req.destroy();
        reject(new Error('websocket handshake timed out'));
      }, timeoutMs);
      timer.unref?.();

      req.on('upgrade', (res, socket, head) => {
        clearTimeout(timer);
        if (res.statusCode !== 101) {
          socket.destroy();
          return reject(new Error(`websocket upgrade refused: ${res.statusCode}`));
        }

        this.#socket = socket;
        socket.setNoDelay(true);

        // Bytes may already have arrived alongside the upgrade response.
        if (head?.length) this.#feed(head);

        socket.on('data', (chunk: Buffer) => this.#feed(chunk));
        socket.on('close', () => this.#finish());
        socket.on('error', (err) => {
          this.#handlers.onError?.(err);
          this.#finish();
        });

        resolve();
      });

      req.on('response', (res) => {
        clearTimeout(timer);
        res.destroy();
        reject(new Error(`websocket upgrade refused: ${res.statusCode}`));
      });

      req.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });

      req.end();
    });
  }

  send(data: string): void {
    const socket = this.#socket;
    if (!socket || socket.destroyed) throw new Error('websocket not connected');
    socket.write(this.#frame(Buffer.from(data, 'utf8'), OPCODE.text));
  }

  close(): void {
    if (this.#closed) return;
    const socket = this.#socket;
    if (socket && !socket.destroyed) {
      try {
        socket.write(this.#frame(Buffer.alloc(0), OPCODE.close));
      } catch {
        // Peer already gone.
      }
      socket.destroy();
    }
    this.#finish();
  }

  #finish(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#handlers.onClose?.();
  }

  /**
   * Build a client frame. Clients must mask their payload; the mask is a
   * 4-byte key XORed over the data.
   */
  #frame(payload: Buffer, opcode: number): Buffer {
    const length = payload.length;
    let header: Buffer;

    if (length < 126) {
      header = Buffer.alloc(2);
      header[1] = 0x80 | length;
    } else if (length < 65536) {
      header = Buffer.alloc(4);
      header[1] = 0x80 | 126;
      header.writeUInt16BE(length, 2);
    } else {
      header = Buffer.alloc(10);
      header[1] = 0x80 | 127;
      header.writeBigUInt64BE(BigInt(length), 2);
    }
    header[0] = 0x80 | opcode; // FIN + opcode

    const mask = randomBytes(4);
    const masked = Buffer.allocUnsafe(length);
    for (let i = 0; i < length; i++) {
      masked[i] = payload[i]! ^ mask[i % 4]!;
    }

    return Buffer.concat([header, mask, masked]);
  }

  /** Accumulate bytes and drain every complete frame available. */
  #feed(chunk: Buffer): void {
    this.#buffer = this.#buffer.length === 0 ? chunk : Buffer.concat([this.#buffer, chunk]);

    for (;;) {
      const frame = this.#readFrame();
      if (!frame) return;

      switch (frame.opcode) {
        case OPCODE.text:
        case OPCODE.binary:
          if (frame.fin) {
            this.#handlers.onMessage?.(frame.payload.toString('utf8'));
          } else {
            this.#fragmentOpcode = frame.opcode;
            this.#fragments = [frame.payload];
          }
          break;

        case OPCODE.continuation: {
          this.#fragments.push(frame.payload);
          if (frame.fin) {
            const full = Buffer.concat(this.#fragments);
            this.#fragments = [];
            this.#fragmentOpcode = 0;
            this.#handlers.onMessage?.(full.toString('utf8'));
          }
          break;
        }

        case OPCODE.ping:
          // Keep the connection alive; CDP itself never pings, but be correct.
          this.#socket?.write(this.#frame(frame.payload, OPCODE.pong));
          break;

        case OPCODE.close:
          this.close();
          return;

        default:
          break;
      }
    }
  }

  /**
   * Parse one frame off the head of the buffer, or return undefined when more
   * bytes are needed. Server frames are never masked.
   */
  #readFrame(): { fin: boolean; opcode: number; payload: Buffer } | undefined {
    const buffer = this.#buffer;
    if (buffer.length < 2) return undefined;

    const first = buffer[0]!;
    const second = buffer[1]!;
    const fin = (first & 0x80) !== 0;
    const opcode = first & 0x0f;
    const masked = (second & 0x80) !== 0;
    let length = second & 0x7f;
    let offset = 2;

    if (length === 126) {
      if (buffer.length < offset + 2) return undefined;
      length = buffer.readUInt16BE(offset);
      offset += 2;
    } else if (length === 127) {
      if (buffer.length < offset + 8) return undefined;
      const big = buffer.readBigUInt64BE(offset);
      // A CDP screenshot is a few hundred KB; anything near 2^53 is nonsense.
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
        this.#handlers.onError?.(new Error('websocket frame too large'));
        this.close();
        return undefined;
      }
      length = Number(big);
      offset += 8;
    }

    const maskKey = masked ? buffer.subarray(offset, offset + 4) : undefined;
    if (masked) offset += 4;

    if (buffer.length < offset + length) return undefined;

    let payload = buffer.subarray(offset, offset + length);
    if (maskKey) {
      const unmasked = Buffer.allocUnsafe(length);
      for (let i = 0; i < length; i++) unmasked[i] = payload[i]! ^ maskKey[i % 4]!;
      payload = unmasked;
    } else {
      // subarray aliases the buffer we are about to discard; copy it out.
      payload = Buffer.from(payload);
    }

    this.#buffer = buffer.subarray(offset + length);
    return { fin, opcode, payload };
  }
}
