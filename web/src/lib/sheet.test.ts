import { describe, expect, it } from 'vitest';
import { literal, winAnsi, wrap } from './pdf';
import { emergencySheet } from './sheet';

const text = (bytes: Uint8Array) => new TextDecoder('latin1').decode(bytes);

describe('the emergency sheet', () => {
  const sheet = (recoveryCode: string | null) =>
    text(
      emergencySheet({
        server: 'https://lock.example.com',
        email: 'nyu@example.com',
        recoveryCode,
        contacts: [{ name: 'Mika', email: 'mika@example.com', type: 1, waitTimeDays: 7 }],
        language: 'de',
        date: new Date('2026-09-28T12:00:00Z'),
      }),
    );

  it('is a PDF whose cross-reference table points at its objects', () => {
    const pdf = sheet('abcd efgh ijkl mnop qrst uvwx yz12 3456');
    expect(pdf.startsWith('%PDF-1.4\n')).toBe(true);
    expect(pdf.trimEnd().endsWith('%%EOF')).toBe(true);
    const xref = Number(pdf.match(/startxref\n(\d+)/)![1]);
    expect(pdf.slice(xref, xref + 4)).toBe('xref');
    const offsets = [...pdf.slice(xref).matchAll(/^(\d{10}) 00000 n $/gm)].map((m) => Number(m[1]));
    offsets.forEach((offset, index) => {
      expect(pdf.slice(offset).startsWith(`${index + 1} 0 obj`)).toBe(true);
    });
    const length = Number(pdf.match(/\/Length (\d+) >>\nstream\n/)![1]);
    const start = pdf.indexOf('stream\n') + 'stream\n'.length;
    expect(pdf.slice(start + length, start + length + 10)).toBe('\nendstream');
  });

  it('carries the addresses, the code in groups, the contacts and QR codes', () => {
    const pdf = sheet('abcdefghijklmnop');
    expect(pdf).toContain('(https://lock.example.com)');
    expect(pdf).toContain('(nyu@example.com)');
    expect(pdf).toContain('(ABCD EFGH IJKL MNOP)');
    expect(pdf).toContain('Mika <mika@example.com>');
    expect(pdf).toContain('Wartezeit 7 Tage');
    // Two QR codes: many small filled squares.
    expect((pdf.match(/ re/g) ?? []).length).toBeGreaterThan(200);
    expect(sheet(null)).toContain('keine Zwei-Schritt-Anmeldung');
  });
});

describe('the PDF writer', () => {
  it('writes German in WinAnsi, escaped', () => {
    expect(winAnsi('äß–€✧')).toEqual([0xe4, 0xdf, 0x96, 0x80, 0x3f]);
    expect(literal('Grüße (a\\b)')).toBe('(Gr\\374\\337e \\(a\\\\b\\))');
  });

  it('wraps words into lines that fit, and cuts ones that do not', () => {
    const lines = wrap('ein zwei drei vier fünf sechs', 'regular', 10, 60);
    expect(lines.length).toBeGreaterThan(1);
    expect(lines.join(' ')).toBe('ein zwei drei vier fünf sechs');
    expect(wrap('x'.repeat(100), 'regular', 10, 50).every((line) => line.length < 100)).toBe(true);
  });
});
