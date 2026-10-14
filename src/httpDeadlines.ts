import type { EventEmitter } from 'node:events';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Socket } from 'node:net';
import tls from 'node:tls';

/**
 * Per-connection request deadlines (round 8, slowloris), the same policy as tl-relayer.
 *
 * Node's own `headersTimeout` and `requestTimeout` did not close stalled connections on the
 * runtime targeted here (Node 24.20): the connections expiry check kept returning zero for a
 * partial header block. Socket inactivity is defeated by a slow drip. This watchdog is the
 * enforcement point for the request phase:
 *
 * - a new connection must deliver its request headers within HEADERS_DEADLINE_MS;
 * - once the headers are in, an unfinished body must arrive within BODY_DEADLINE_MS;
 * - after a response finishes, an idle keep-alive socket is closed after KEEP_ALIVE_IDLE_MS;
 * - an upgraded socket (the WebSocket session) leaves HTTP tracking, so no deadline applies.
 *
 * TLS: the request runs on the TLSSocket from 'secureConnection', so the timers attach there.
 * The raw TCP socket is not timed, because a timer on it would also close a live TLS session.
 * The TLS handshake is bounded by the server option `handshakeTimeout` (see index.ts).
 * Handler time is not covered here; the handlers bound their own outbound calls.
 */
export const HEADERS_DEADLINE_MS = 10_000;
export const BODY_DEADLINE_MS = 30_000;
export const KEEP_ALIVE_IDLE_MS = 60_000;

const timers = new WeakMap<Socket, ReturnType<typeof setTimeout>>();

const clearDeadline = (socket: Socket): void => {
  const timer = timers.get(socket);
  if (timer !== undefined) {
    clearTimeout(timer);
    timers.delete(socket);
  }
};

const armDeadline = (socket: Socket, ms: number): void => {
  clearDeadline(socket);
  const timer = setTimeout(() => {
    timers.delete(socket);
    socket.destroy();
  }, ms);
  timers.set(socket, timer);
};

export function attachRequestDeadlines(server: EventEmitter): void {
  const onSocket = (socket: Socket): void => {
    armDeadline(socket, HEADERS_DEADLINE_MS);
    socket.once('close', () => clearDeadline(socket));
  };
  server.on(server instanceof tls.Server ? 'secureConnection' : 'connection', onSocket);

  server.on('request', (req: IncomingMessage, res: ServerResponse) => {
    const socket = req.socket;
    clearDeadline(socket);
    if (!req.complete) {
      armDeadline(socket, BODY_DEADLINE_MS);
      req.once('end', () => clearDeadline(socket));
    }
    res.once('finish', () => {
      if (!socket.destroyed) armDeadline(socket, KEEP_ALIVE_IDLE_MS);
    });
  });

  // The WebSocket session owns upgraded sockets. Their idle and lifetime rules are not HTTP ones.
  server.on('upgrade', (_req: IncomingMessage, socket: Socket) => {
    clearDeadline(socket);
  });
}
