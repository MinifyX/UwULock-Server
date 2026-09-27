import { describe, expect, it } from 'vitest';
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
});
