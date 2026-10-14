import type { WebSocket } from 'ws';
import type { TapeEntryV1, WireMsg } from './types.js';
import { TokenBucket } from './ratelimit.js';

export interface SessionMetaV1 {
  remoteIp?: string;
  userAgent?: string;
  asn?: number;
  vpn?: boolean;
  firstSeenTs: number;
  lastSeenTs: number;
}

/**
 * Largest amount of outgoing data a DataChannel may hold unsent (round 8). A peer that stops
 * reading keeps its channel open, so without this bound every tape broadcast queued for it stays
 * in native memory until the process dies. Past the bound the channel is closed; the wallet
 * resyncs with TAPE_SUB on reconnect.
 */
export const DC_MAX_BUFFERED_BYTES = 4 * 1024 * 1024;

export class PeerSession {
  readonly id: string;
  readonly ws: WebSocket;
  dc: RTCDataChannel | null = null;

  // If true, peer has requested tape feed (or we treat all as subscribers).
  wantsTape: boolean = false;

  // SUBMIT rate limit (per-peer).
  submitBucket: TokenBucket;

  meta: SessionMetaV1;

  constructor(opts: { id: string; ws: WebSocket; burst: number; ratePerSec: number; remoteIp?: string; userAgent?: string }) {
    this.id = opts.id;
    this.ws = opts.ws;
    this.submitBucket = new TokenBucket({ capacity: opts.burst, refillPerSec: opts.ratePerSec });
    const now = Date.now();
    this.meta = {
      remoteIp: opts.remoteIp,
      userAgent: opts.userAgent,
      firstSeenTs: now,
      lastSeenTs: now,
    };
  }

  /**
   * Adopts the channel the peer just opened. A peer may open several channels on one connection;
   * the previous one is closed here, so only one channel per session can hold state or memory.
   */
  attachDataChannel(dc: RTCDataChannel): void {
    const previous = this.dc;
    this.dc = dc;
    if (previous && previous !== dc) {
      try {
        previous.close();
      } catch {}
    }
  }

  /**
   * Sends one message on the session's channel. It never throws: a failed or stalled send closes
   * the channel, which removes the session from the live feed and the idle reaper takes it from there.
   * Returns true when the message was handed to the channel.
   */
  sendDc(msg: WireMsg): boolean {
    const dc = this.dc;
    if (!dc || dc.readyState !== 'open') return false;
    if (dc.bufferedAmount > DC_MAX_BUFFERED_BYTES) {
      this.dropChannel();
      return false;
    }
    try {
      dc.send(JSON.stringify(msg));
      return true;
    } catch {
      this.dropChannel();
      return false;
    }
  }

  sendTapeEntry(entry: TapeEntryV1): boolean {
    return this.sendDc({ t: 'TAPE_ENTRY', v: 1, entry });
  }

  private dropChannel(): void {
    const dc = this.dc;
    this.dc = null;
    try {
      dc?.close();
    } catch {}
  }
}

/**
 * Live tape broadcast. Each subscriber is isolated: one peer whose send fails or stalls can not
 * stop the others from receiving the entry, and the caller (a SUBMIT that is already committed
 * to the tape) never sees an error from this step.
 */
export function broadcastTapeEntry(peers: Iterable<PeerSession>, entry: TapeEntryV1): void {
  for (const peer of peers) {
    if (!peer.dc || peer.dc.readyState !== 'open') continue;
    if (!peer.wantsTape) continue;
    peer.sendTapeEntry(entry);
  }
}
