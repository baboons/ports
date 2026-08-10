import type { ServerResponse } from 'node:http';
import type { ServerEvent } from '../shared/types.ts';

interface Client {
  id: number;
  res: ServerResponse;
}

/**
 * Fan-out hub for Server-Sent Events.
 *
 * SSE rather than WebSocket because the traffic is one-directional and
 * EventSource reconnects on its own; a socket would mean hand-rolling that.
 */
export function createHub() {
  const clients = new Set<Client>();
  let nextId = 1;
  let lastEventId = 0;

  /** Coalescing buffer so a burst of record updates becomes one frame. */
  let pending: ServerEvent[] = [];
  let flushTimer: NodeJS.Timeout | undefined;

  const writeEvent = (client: Client, event: ServerEvent, id: number): boolean => {
    try {
      return client.res.write(`id: ${id}\ndata: ${JSON.stringify(event)}\n\n`);
    } catch {
      // A client that vanished mid-write is dropped on the next sweep.
      return false;
    }
  };

  const broadcast = (event: ServerEvent) => {
    const id = ++lastEventId;
    for (const client of [...clients]) {
      if (!writeEvent(client, event, id)) {
        clients.delete(client);
      }
    }
  };

  const flush = () => {
    flushTimer = undefined;
    if (pending.length === 0) return;

    // Merge queued upserts into a single event; the UI applies them as a batch.
    const upserts = new Map<string, unknown>();
    const rest: ServerEvent[] = [];
    for (const event of pending) {
      if (event.type === 'upsert') {
        for (const record of event.records) upserts.set(record.id, record);
      } else {
        rest.push(event);
      }
    }
    pending = [];

    if (upserts.size > 0) {
      broadcast({
        type: 'upsert',
        records: [...upserts.values()] as never,
      });
    }
    for (const event of rest) broadcast(event);
  };

  return {
    get size() {
      return clients.size;
    },

    add(res: ServerResponse): () => void {
      res.writeHead(200, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-cache, no-transform',
        connection: 'keep-alive',
        // Without this an intervening proxy may buffer the stream forever.
        'x-accel-buffering': 'no',
      });
      // Tell EventSource to come straight back if the process restarts.
      res.write('retry: 2000\n\n');

      const client: Client = { id: nextId++, res };
      clients.add(client);

      const remove = () => clients.delete(client);
      res.on('close', remove);
      res.on('error', remove);
      return remove;
    },

    /** Queue an event; delivery is batched on a short timer. */
    send(event: ServerEvent) {
      pending.push(event);
      if (!flushTimer) {
        flushTimer = setTimeout(flush, 100);
        flushTimer.unref?.();
      }
    },

    /** Deliver immediately, for events the UI should not wait on. */
    sendNow(event: ServerEvent) {
      flush();
      broadcast(event);
    },

    /** Comment frames keep intermediaries from closing an idle connection. */
    heartbeat() {
      for (const client of [...clients]) {
        try {
          client.res.write(': ping\n\n');
        } catch {
          clients.delete(client);
        }
      }
    },

    closeAll() {
      for (const client of clients) {
        try {
          client.res.end();
        } catch {
          // Already gone.
        }
      }
      clients.clear();
    },
  };
}

export type Hub = ReturnType<typeof createHub>;
