import { describe, expect, it } from 'vitest';
import { fromLocalInput, labelsText, localInput, parseLabels, randomToken } from './admin';

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
