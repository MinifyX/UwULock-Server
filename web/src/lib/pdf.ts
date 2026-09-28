/**
 * A small PDF writer: A4 pages with text in the standard fonts, rectangles and lines — enough
 * for the emergency sheet, which is made here in the browser so the server never sees it.
 *
 * The standard 14 fonts need nothing embedded; they are drawn in WinAnsiEncoding, which covers
 * German and English. What it does not cover becomes `?`. Nothing is compressed: the sheet is a
 * few kilobytes either way, and a plain file is easy to check.
 */

export type Font = 'regular' | 'bold' | 'mono';

const FONTS: Record<Font, { name: string; base: string }> = {
  regular: { name: 'F1', base: 'Helvetica' },
  bold: { name: 'F2', base: 'Helvetica-Bold' },
  mono: { name: 'F3', base: 'Courier-Bold' },
};

/** A4, in points. */
export const PAGE = { width: 595.28, height: 841.89 };

/** Helvetica's widths for the characters 32 to 126, in thousandths of the font size. */
const HELVETICA = [
  278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
  556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667,
  611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
  667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500,
  222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
];

/** Where WinAnsiEncoding differs from Latin-1: the characters it has in 0x80–0x9F. */
const WIN_ANSI: Record<string, number> = {
  '€': 0x80,
  '‚': 0x82,
  '„': 0x84,
  '…': 0x85,
  '‘': 0x91,
  '’': 0x92,
  '“': 0x93,
  '”': 0x94,
  '•': 0x95,
  '–': 0x96,
  '—': 0x97,
  '‹': 0x8b,
  '›': 0x9b,
};

/** The bytes of `text` in WinAnsiEncoding. */
export function winAnsi(text: string): number[] {
  const bytes: number[] = [];
  for (const char of text) {
    const code = char.codePointAt(0)!;
    if (WIN_ANSI[char] !== undefined) bytes.push(WIN_ANSI[char]);
    else if (code === 0x0a || code === 0x0d || code === 0x09) bytes.push(0x20);
    else if (code >= 0x20 && code < 0x7f) bytes.push(code);
    else if (code >= 0xa0 && code <= 0xff) bytes.push(code);
    else bytes.push(0x3f);
  }
  return bytes;
}

/** A PDF string literal of `text`: ASCII as it is, `(`, `)` and `\` escaped, the rest in octal. */
export function literal(text: string): string {
  let out = '(';
  for (const byte of winAnsi(text)) {
    if (byte === 0x28 || byte === 0x29 || byte === 0x5c) out += `\\${String.fromCharCode(byte)}`;
    else if (byte >= 0x20 && byte < 0x7f) out += String.fromCharCode(byte);
    else out += `\\${byte.toString(8).padStart(3, '0')}`;
  }
  return `${out})`;
}

/** How wide `text` is in `font` at `size` points. */
export function width(text: string, font: Font, size: number): number {
  if (font === 'mono') return [...text].length * 600 * (size / 1000);
  let total = 0;
  for (const byte of winAnsi(text)) {
    total += byte >= 32 && byte <= 126 ? HELVETICA[byte - 32]! : 556;
  }
  // Helvetica-Bold is a little wider; this keeps wrapped lines inside their box.
  return total * (size / 1000) * (font === 'bold' ? 1.06 : 1);
}

/** `text` in lines no wider than `max` points. Words longer than a line are cut. */
export function wrap(text: string, font: Font, size: number, max: number): string[] {
  const lines: string[] = [];
  for (const paragraph of text.split('\n')) {
    let line = '';
    for (const word of paragraph.split(/\s+/).filter(Boolean)) {
      const next = line ? `${line} ${word}` : word;
      if (width(next, font, size) <= max) {
        line = next;
        continue;
      }
      if (line) lines.push(line);
      let rest = word;
      while (width(rest, font, size) > max && rest.length > 1) {
        let cut = rest.length - 1;
        while (cut > 1 && width(rest.slice(0, cut), font, size) > max) cut--;
        lines.push(rest.slice(0, cut));
        rest = rest.slice(cut);
      }
      line = rest;
    }
    lines.push(line);
  }
  return lines;
}

const number = (value: number) => (Math.round(value * 100) / 100).toString();

/** A page being drawn: coordinates from the top left, in points, like the rest of the page. */
export class Page {
  readonly ops: string[] = [];

  text(x: number, top: number, text: string, size = 11, font: Font = 'regular', gray = 0) {
    const y = PAGE.height - top - size;
    this.ops.push(
      `BT ${number(gray)} g /${FONTS[font].name} ${number(size)} Tf ${number(x)} ${number(y)} Td ${literal(text)} Tj ET`,
    );
  }

  /** Wrapped text; answers where the next line would begin. */
  paragraph(
    x: number,
    top: number,
    text: string,
    max: number,
    size = 11,
    font: Font = 'regular',
    gray = 0,
  ): number {
    const leading = size * 1.35;
    for (const line of wrap(text, font, size, max)) {
      this.text(x, top, line, size, font, gray);
      top += leading;
    }
    return top;
  }

  rect(x: number, top: number, w: number, h: number, fill = true, gray = 0) {
    const y = PAGE.height - top - h;
    const shape = `${number(x)} ${number(y)} ${number(w)} ${number(h)} re`;
    this.ops.push(fill ? `${number(gray)} g ${shape} f` : `${number(gray)} G 0.8 w ${shape} S`);
  }

  line(x1: number, top1: number, x2: number, top2: number, gray = 0.6) {
    this.ops.push(
      `${number(gray)} G 0.6 w ${number(x1)} ${number(PAGE.height - top1)} m ${number(x2)} ${number(PAGE.height - top2)} l S`,
    );
  }

  /** A QR code's modules, `data[row][column]`, as filled squares in a `size` point square. */
  qr(x: number, top: number, size: number, data: boolean[][]) {
    const modules = data.length;
    const cell = size / modules;
    const squares: string[] = [];
    data.forEach((row, r) =>
      row.forEach((dark, c) => {
        if (!dark) return;
        const y = PAGE.height - top - (r + 1) * cell;
        squares.push(`${number(x + c * cell)} ${number(y)} ${number(cell)} ${number(cell)} re`);
      }),
    );
    this.ops.push(`0 g ${squares.join(' ')} f`);
  }
}

export class Pdf {
  readonly pages: Page[] = [];

  page(): Page {
    const page = new Page();
    this.pages.push(page);
    return page;
  }

  /** The finished file. */
  bytes(title: string): Uint8Array {
    const objects: string[] = [];
    const add = (body: string) => {
      objects.push(body);
      return objects.length;
    };
    const catalog = add('');
    const pages = add('');
    const info = add(`<< /Title ${literal(title)} /Producer (UwULock) >>`);
    const fonts = (Object.keys(FONTS) as Font[]).map((font) =>
      add(
        `<< /Type /Font /Subtype /Type1 /BaseFont /${FONTS[font].base} /Encoding /WinAnsiEncoding >>`,
      ),
    );
    const resources = `<< /Font << ${(Object.keys(FONTS) as Font[])
      .map((font, index) => `/${FONTS[font].name} ${fonts[index]} 0 R`)
      .join(' ')} >> >>`;
    const kids = this.pages.map((page) => {
      const content = page.ops.join('\n');
      const stream = add(`<< /Length ${content.length} >>\nstream\n${content}\nendstream`);
      return add(
        `<< /Type /Page /Parent ${pages} 0 R /MediaBox [0 0 ${number(PAGE.width)} ${number(PAGE.height)}] /Resources ${resources} /Contents ${stream} 0 R >>`,
      );
    });
    objects[catalog - 1] = `<< /Type /Catalog /Pages ${pages} 0 R >>`;
    objects[pages - 1] =
      `<< /Type /Pages /Kids [${kids.map((kid) => `${kid} 0 R`).join(' ')}] /Count ${kids.length} >>`;

    // Everything above is ASCII, so a character is a byte and the offsets are right.
    let out = '%PDF-1.4\n';
    const offsets: number[] = [];
    objects.forEach((body, index) => {
      offsets.push(out.length);
      out += `${index + 1} 0 obj\n${body}\nendobj\n`;
    });
    const xref = out.length;
    out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
    for (const offset of offsets) out += `${String(offset).padStart(10, '0')} 00000 n \n`;
    out += `trailer\n<< /Size ${objects.length + 1} /Root ${catalog} 0 R /Info ${info} 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
    return new TextEncoder().encode(out);
  }
}
