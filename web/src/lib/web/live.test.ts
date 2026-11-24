import { describe, expect, it, vi } from 'vitest';
import { updates } from './live';

// What uwulock-notify writes for a folder that changed on another device: the invocation
// [1, {}, null, "ReceiveMessage", [{ContextId, Type, Payload: {Id, UserId, RevisionDate}}]],
// with its length in front.
function frame(message: number[]): Uint8Array {
  return new Uint8Array([message.length, ...message]);
}
const text = (value: string) => [0xa0 | value.length, ...new TextEncoder().encode(value)];

function invocation(type: number, context: string | null): number[] {
  return [
    0x95,
    0x01,
    0x80,
    0xc0,
    ...text('ReceiveMessage'),
    0x91,
    0x83,
    ...text('ContextId'),
    ...(context === null ? [0xc0] : text(context)),
    ...text('Type'),
    type,
    ...text('Payload'),
    0x82,
    ...text('Id'),
    ...text('f1'),
    ...text('RevisionDate'),
    // A timestamp extension (fixext 8), as the server writes dates.
    0xd7,
    0xff,
    0,
    0,
    0,
    0,
    0x66,
    0xf6,
    0x7e,
    0x80,
  ];
}

describe('the hub', () => {
  it('reads updates, with the device they came from', () => {
    expect(updates(frame(invocation(7, 'laptop')))).toEqual([{ type: 7, contextId: 'laptop' }]);
    expect(updates(frame(invocation(15, null)))).toEqual([{ type: 15, contextId: null }]);
  });

  it('reads several messages in one frame', () => {
    const both = new Uint8Array([...frame(invocation(1, 'a')), ...frame(invocation(2, 'b'))]);
    expect(updates(both).map((update) => update.type)).toEqual([1, 2]);
  });

  it('leaves out pings, the handshake and what it cannot read', () => {
    expect(updates(frame([0x91, 0x06]))).toEqual([]);
    expect(updates(new TextEncoder().encode('{}\u001e'))).toEqual([]);
    expect(updates(frame([0x95, 0x01, 0xc1]))).toEqual([]);
  });

  it('stops at a length that does not fit, at once', () => {
    expect(updates(new Uint8Array([0x80, 0x80, 0x80, 0x80, 0x08, 0x91, 0x06]))).toEqual([]);
    expect(updates(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]))).toEqual([]);
    expect(updates(new Uint8Array([0x10, 0x91]))).toEqual([]);
  });
});

describe('the connection', () => {
  it('syncs once it is back after a drop, not on the first connect', async () => {
    vi.resetModules();
    const emitted: string[] = [];
    vi.doMock('../events', () => ({ emit: (name: string) => emitted.push(name) }));
    vi.doMock('./http', () => ({ deviceId: () => 'd1', freshToken: async () => 'token' }));
    const sockets: FakeSocket[] = [];
    class FakeSocket {
      binaryType = '';
      onopen: (() => void) | null = null;
      onclose: (() => void) | null = null;
      onmessage: unknown = null;
      constructor() {
        sockets.push(this);
      }
      send() {}
      close() {}
    }
    vi.stubGlobal('WebSocket', FakeSocket);
    vi.useFakeTimers();
    try {
      const live = await import('./live');
      live.startLive();
      await vi.waitFor(() => expect(sockets).toHaveLength(1));
      sockets[0]!.onopen!();
      expect(emitted).toEqual([]);
      sockets[0]!.onclose!();
      await vi.runOnlyPendingTimersAsync();
      await vi.waitFor(() => expect(sockets).toHaveLength(2));
      sockets[1]!.onopen!();
      expect(emitted).toEqual(['hub-sync']);
      live.stopLive();
    } finally {
      vi.useRealTimers();
      vi.unstubAllGlobals();
      vi.doUnmock('../events');
      vi.doUnmock('./http');
    }
  });
});
