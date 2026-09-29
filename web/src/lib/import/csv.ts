/**
 * CSV as RFC 4180 writes it, and as password managers actually write it: quoted cells with
 * doubled quotes, line breaks inside quotes, CRLF or LF, a byte order mark in front, and a
 * stray quote in the middle of a cell taken as it is.
 */

export function parseCsv(input: string, delimiter = ','): string[][] {
  const text = input.replace(/^\uFEFF/, '');
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let quoted = false;
  // Whether the current cell began with a quote: only then does a quote end it.
  let wasQuoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          cell += '"';
          i++;
        } else {
          quoted = false;
        }
      } else if (c === '\r' && text[i + 1] === '\n') {
        // A line break inside a cell is a line break, whatever the file's own ones are.
        cell += '\n';
        i++;
      } else {
        cell += c;
      }
      continue;
    }
    if (c === '"' && cell === '' && !wasQuoted) {
      quoted = true;
      wasQuoted = true;
    } else if (c === delimiter) {
      row.push(cell);
      cell = '';
      wasQuoted = false;
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = '';
      wasQuoted = false;
    } else {
      cell += c;
    }
  }
  if (cell !== '' || row.length > 0 || wasQuoted) {
    row.push(cell);
    rows.push(row);
  }
  return rows.filter((cells) => cells.some((cell) => cell.trim() !== ''));
}

/** A CSV file with a header row: cells by column name, names compared without case. */
export class CsvTable {
  readonly header: string[];
  readonly rows: string[][];
  private index = new Map<string, number>();

  constructor(text: string) {
    const [header = [], ...rows] = parseCsv(text);
    this.header = header.map((name) => name.trim());
    this.rows = rows;
    this.header.forEach((name, i) => {
      const key = name.toLowerCase();
      if (!this.index.has(key)) this.index.set(key, i);
    });
  }

  has(...names: string[]): boolean {
    return names.every((name) => this.index.has(name.toLowerCase()));
  }

  /** The cell of `row` in the first of `names` the file has, trimmed; '' when there is none. */
  get(row: string[], ...names: string[]): string {
    for (const name of names) {
      const i = this.index.get(name.toLowerCase());
      if (i !== undefined) return (row[i] ?? '').trim();
    }
    return '';
  }

  /** The row's cells with their column names, for the columns not in `known`. */
  rest(row: string[], known: string[]): [string, string][] {
    const skip = new Set(known.map((name) => name.toLowerCase()));
    return this.header
      .map((name, i): [string, string] => [name, (row[i] ?? '').trim()])
      .filter(([name, value]) => name && value && !skip.has(name.toLowerCase()));
  }
}
