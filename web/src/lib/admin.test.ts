import { describe, expect, it } from 'vitest';
import {
  blockPrefill,
  fromLocalInput,
  labelsText,
  localInput,
  parseLabels,
  placeText,
  randomToken,
} from './admin';

describe('Loki labels', () => {
  it('go to name=value lines and back', () => {
    const labels = { job: 'uwulock', host: 'vault-1' };
    expect(parseLabels(labelsText(labels))).toEqual({ labels, bad: [] });
  });

  it('skip empty lines, trim, and name what is not a label', () => {
    expect(parseLabels(' job = uwulock \n\n=x\n1a=b\nnovalue=\njust text')).toEqual({
      labels: { job: 'uwulock' },
      bad: ['=x', '1a=b', 'novalue=', 'just text'],
    });
  });

  it('keep an equals sign in the value', () => {
    expect(parseLabels('env=a=b').labels).toEqual({ env: 'a=b' });
  });
});

describe('the metrics token', () => {
  it('is 32 letters and digits, different each time', () => {
    const one = randomToken();
    expect(one).toMatch(/^[A-Za-z0-9]{32}$/);
    expect(randomToken()).not.toBe(one);
  });
});

describe('the deadline', () => {
  it('goes to the local input and back to the same moment', () => {
    const iso = '2026-10-01T08:30:00Z';
    expect(fromLocalInput(localInput(iso))).toBe(iso);
    expect(localInput(null)).toBe('');
    expect(fromLocalInput('')).toBeNull();
  });
});

describe('where an address is', () => {
  it('reads as city, country and network, with what there is', () => {
    expect(
      placeText({
        city: 'Berlin',
        country: 'DE',
        countryName: 'Deutschland',
        asn: 64496,
        network: 'Example Net',
      }),
    ).toBe('Berlin, Deutschland · Example Net (AS64496)');
    expect(placeText({ country: 'AT' })).toBe('AT');
    expect(placeText({ asn: 64497 })).toBe('AS64497');
    expect(placeText({})).toBeNull();
    expect(placeText(null)).toBeNull();
  });
});

describe('the address the block dialog starts with', () => {
  it("is an IPv6 address's /64, an IPv4 address as it is", () => {
    expect(blockPrefill('203.0.113.7')).toBe('203.0.113.7');
    expect(blockPrefill('2001:db8:1:2:3:4:5:6')).toBe('2001:db8:1:2::/64');
    expect(blockPrefill('2001:db8:1:2::abcd')).toBe('2001:db8:1:2::/64');
    expect(blockPrefill('2001:DB8::1')).toBe('2001:db8::/64');
    expect(blockPrefill('2001:db8:0:5::1')).toBe('2001:db8:0:5::/64');
    expect(blockPrefill('fe80::1%eth0')).toBe('fe80::/64');
    expect(blockPrefill('::1')).toBe('::/64');
    expect(blockPrefill('::ffff:192.0.2.1')).toBe('192.0.2.1');
  });

  it('leaves networks, empty and unreadable text alone', () => {
    expect(blockPrefill('2001:db8::/48')).toBe('2001:db8::/48');
    expect(blockPrefill('198.51.100.0/24')).toBe('198.51.100.0/24');
    expect(blockPrefill('')).toBe('');
    expect(blockPrefill('2001:db8::1::2')).toBe('2001:db8::1::2');
    expect(blockPrefill('2001:db8:zz::1')).toBe('2001:db8:zz::1');
    expect(blockPrefill('1:2:3:4:5:6:7:8:9')).toBe('1:2:3:4:5:6:7:8:9');
  });
});
