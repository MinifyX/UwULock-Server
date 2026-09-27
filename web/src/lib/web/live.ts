/**
 * Live updates from the server's notification hub — SignalR over a WebSocket, in MessagePack,
 * the same connection Bitwarden's apps keep open. A change made on another device shows here at
 * once instead of on the next sync. Only while the vault is open; a dropped connection is tried
 * again, a little later each time.
 */

import { emit } from '../events';
import { deviceId, freshToken } from './http';

/** Bitwarden's update types that need more than a sync. */
const LOG_OUT = 11;
const AUTH_REQUEST = 15;

export type Update = { type: number; contextId: string | null };

// ── Just enough MessagePack to read SignalR's invocations ───

class Reader {
  at = 0;
  constructor(private bytes: Uint8Array) {}
  private view = () =>
    new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength);
  private take(count: number): Uint8Array {
    if (this.at + count > this.bytes.length) throw new Error('truncated');
    const out = this.bytes.subarray(this.at, this.at + count);
    this.at += count;
    return out;
  }
  private uint(size: 1 | 2 | 4): number {
    const at = this.at;
    this.take(size);
    const view = this.view();
    return size === 1 ? view.getUint8(at) : size === 2 ? view.getUint16(at) : view.getUint32(at);
  }
  private text(length: number) {
    return new TextDecoder().decode(this.take(length));
  }
  private array(length: number): unknown[] {
    return Array.from({ length }, () => this.value());
  }
  private map(length: number): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (let i = 0; i < length; i++) {
      const key = this.value();
      out[String(key)] = this.value();
    }
    return out;
  }

  value(): unknown {
    const tag = this.uint(1);
    if (tag <= 0x7f) return tag;
    if (tag >= 0xe0) return tag - 0x100;
    if ((tag & 0xf0) === 0x80) return this.map(tag & 0x0f);
    if ((tag & 0xf0) === 0x90) return this.array(tag & 0x0f);
    if ((tag & 0xe0) === 0xa0) return this.text(tag & 0x1f);
    const view = this.view();
    const at = this.at;
    switch (tag) {
      case 0xc0:
        return null;
      case 0xc2:
        return false;
      case 0xc3:
        return true;
      case 0xc4:
      case 0xc5:
      case 0xc6:
        return this.take(this.uint(tag === 0xc4 ? 1 : tag === 0xc5 ? 2 : 4));
      case 0xc7:
      case 0xc8:
      case 0xc9: {
        // An extension, such as a timestamp: skipped, nothing here needs one.
        const length = this.uint(tag === 0xc7 ? 1 : tag === 0xc8 ? 2 : 4);
        this.take(length + 1);
        return null;
      }
      case 0xca:
        this.take(4);
        return view.getFloat32(at);
      case 0xcb:
        this.take(8);
        return view.getFloat64(at);
      case 0xcc:
        return this.uint(1);
      case 0xcd:
        return this.uint(2);
      case 0xce:
        return this.uint(4);
      case 0xcf:
        this.take(8);
        return Number(view.getBigUint64(at));
      case 0xd0:
        this.take(1);
        return view.getInt8(at);
      case 0xd1:
        this.take(2);
        return view.getInt16(at);
      case 0xd2:
        this.take(4);
        return view.getInt32(at);
      case 0xd3:
        this.take(8);
        return Number(view.getBigInt64(at));
      case 0xd4:
      case 0xd5:
      case 0xd6:
      case 0xd7:
      case 0xd8:
        this.take(1 + 2 ** (tag - 0xd4));
        return null;
      case 0xd9:
      case 0xda:
      case 0xdb:
        return this.text(this.uint(tag === 0xd9 ? 1 : tag === 0xda ? 2 : 4));
      case 0xdc:
      case 0xdd:
        return this.array(this.uint(tag === 0xdc ? 2 : 4));
      case 0xde:
      case 0xdf:
        return this.map(this.uint(tag === 0xde ? 2 : 4));
      default:
        throw new Error(`MessagePack tag ${tag}`);
    }
  }
}

/**
 * The updates in one frame of the hub: each message has its length in front, seven bits a
 * byte; an invocation of `ReceiveMessage` carries one update. Pings, the handshake's answer and
 * anything else are left out.
 */
export function updates(frame: Uint8Array): Update[] {
  const out: Update[] = [];
  let at = 0;
  // The handshake's answer is JSON: `{}` and a record separator.
  if (frame[0] === 0x7b) return out;
  while (at < frame.length) {
    let length = 0;
    let shift = 0;
    let byte: number;
    do {
      byte = frame[at++] ?? 0;
      length |= (byte & 0x7f) << shift;
      shift += 7;
    } while (byte & 0x80 && at < frame.length);
    const message = frame.subarray(at, at + length);
    at += length;
    try {
      const value = new Reader(message).value();
      if (!Array.isArray(value) || value[0] !== 1 || value[3] !== 'ReceiveMessage') continue;
      const argument = (value[4] as unknown[] | undefined)?.[0] as
        Record<string, unknown> | undefined;
      if (typeof argument?.Type !== 'number') continue;
      out.push({
        type: argument.Type,
        contextId: typeof argument.ContextId === 'string' ? argument.ContextId : null,
      });
    } catch {
      // Something this page does not read: the next sync brings it anyway.
    }
  }
  return out;
}

// ── The connection ────────────────────────────────────────

let socket: WebSocket | null = null;
let wanted = false;
let failures = 0;
let retry: number | undefined;
let settle: number | undefined;

function handle(update: Update) {
  // What this browser did itself, it knows already.
  if (update.contextId === deviceId()) return;
  if (update.type === AUTH_REQUEST) {
    emit('auth-request');
    return;
  }
  if (update.type === LOG_OUT) {
    emit('hub-logout');
    return;
  }
  // Several changes in a row, one sync.
  window.clearTimeout(settle);
  settle = window.setTimeout(() => emit('hub-sync'), 300);
}

async function connect() {
  if (!wanted || socket) return;
  let token: string | null;
  try {
    token = await freshToken();
  } catch {
    return;
  }
  if (!token || !wanted || socket) return;
  const url = new URL('/notifications/hub', window.location.href);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.searchParams.set('access_token', token);
  const ws = new WebSocket(url);
  ws.binaryType = 'arraybuffer';
  socket = ws;
  ws.onopen = () => ws.send('{"protocol":"messagepack","version":1}\u001e');
  ws.onmessage = (event: MessageEvent) => {
    if (!(event.data instanceof ArrayBuffer)) return;
    failures = 0;
    for (const update of updates(new Uint8Array(event.data))) handle(update);
  };
  ws.onclose = () => {
    if (socket === ws) socket = null;
    if (!wanted) return;
    const delay = Math.min(60_000, 1000 * 2 ** failures++) + Math.random() * 1000;
    retry = window.setTimeout(() => void connect(), delay);
  };
}

/** Listen, while the vault is open. */
export function startLive() {
  if (typeof WebSocket === 'undefined') return;
  wanted = true;
  void connect();
}

/** Stop listening: the vault closed. */
export function stopLive() {
  wanted = false;
  window.clearTimeout(retry);
  window.clearTimeout(settle);
  failures = 0;
  socket?.close();
  socket = null;
}
