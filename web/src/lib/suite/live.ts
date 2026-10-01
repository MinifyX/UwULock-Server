/**
 * UwULock's own realtime channel (docs/uwu-api.md §5), while a suite space is on screen: the
 * apps' pushes are announced there (area `suite`, with the space), not on Bitwarden's hub. It
 * says only *that* a space changed; the page then pulls from its cursor.
 */

import { freshToken } from '../web/http';

type Handler = () => void;

const watchers = new Map<string, Set<Handler>>();
let socket: WebSocket | null = null;
let failures = 0;
let retry: number | undefined;
let ping: number | undefined;
let settle = new Map<string, number>();
/** A connection was up before: after a reconnect, what was missed is pulled. */
let before = false;

function wanted() {
  return [...watchers.values()].some((set) => set.size > 0);
}

/** A `changed` message: the spaces of it whose watchers to call. */
export function changedSpaces(message: unknown): string[] {
  const m = message as { type?: unknown; areas?: unknown; spaces?: unknown } | null;
  if (!m || m.type !== 'changed' || !Array.isArray(m.areas) || !m.areas.includes('suite'))
    return [];
  return Array.isArray(m.spaces) ? m.spaces.filter((s): s is string => typeof s === 'string') : [];
}

function changed(space: string) {
  // Several pushes in a row, one pull.
  window.clearTimeout(settle.get(space));
  settle.set(
    space,
    window.setTimeout(() => watchers.get(space)?.forEach((handler) => handler()), 250),
  );
}

function stop() {
  window.clearTimeout(retry);
  window.clearInterval(ping);
  settle.forEach((timer) => window.clearTimeout(timer));
  settle = new Map();
  failures = 0;
  before = false;
  const ws = socket;
  socket = null;
  ws?.close();
}

async function connect() {
  if (socket || !wanted() || typeof WebSocket === 'undefined') return;
  let token: string | null;
  try {
    token = await freshToken();
  } catch {
    token = null;
  }
  if (!token || socket || !wanted()) return;
  const url = new URL('/uwu/v1/realtime', window.location.href);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(url, 'uwu.realtime.v1');
  socket = ws;
  ws.onopen = () => ws.send(JSON.stringify({ type: 'auth', token, cursor: null }));
  ws.onmessage = (event: MessageEvent) => {
    let message: unknown;
    try {
      message = JSON.parse(String(event.data));
    } catch {
      return;
    }
    const type = (message as { type?: unknown })?.type;
    if (type === 'ready') {
      failures = 0;
      if (before) for (const [space, set] of watchers) if (set.size) changed(space);
      before = true;
      const { heartbeat, expires } = message as { heartbeat?: number; expires?: number };
      window.clearInterval(ping);
      // A browser can't see the server's pings: it asks, so a dead connection shows.
      ping = window.setInterval(
        () => {
          if (ws.readyState === WebSocket.OPEN) ws.send('{"type":"ping"}');
        },
        Math.max(10, heartbeat ?? 25) * 1000,
      );
      // A new token before this one runs out.
      if (expires) {
        const renew = expires * 1000 - Date.now() - 60_000;
        window.setTimeout(
          () =>
            void freshToken().then((fresh) => {
              if (fresh && socket === ws && ws.readyState === WebSocket.OPEN)
                ws.send(JSON.stringify({ type: 'auth', token: fresh, cursor: null }));
            }),
          Math.max(5_000, renew),
        );
      }
      return;
    }
    for (const space of changedSpaces(message)) changed(space);
  };
  ws.onclose = (event: CloseEvent) => {
    if (socket !== ws) return;
    socket = null;
    window.clearInterval(ping);
    if (!wanted() || event.code === 4403) return;
    const base = event.code === 4429 || event.code === 4400 ? 60_000 : 1000 * 2 ** failures++;
    const delay = Math.min(60_000, base) * (0.7 + Math.random() * 0.6);
    retry = window.setTimeout(() => void connect(), delay);
  };
}

/** Call `handler` when an app changed `space`, until the function returned is called. */
export function watchSuite(space: string, handler: Handler): () => void {
  const set = watchers.get(space) ?? new Set<Handler>();
  watchers.set(space, set);
  set.add(handler);
  void connect();
  return () => {
    set.delete(handler);
    if (!wanted()) stop();
  };
}
