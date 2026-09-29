import { describe, expect, it } from 'vitest';
import { CsvTable, parseCsv } from './csv';

describe('the CSV reader', () => {
  it('reads quotes, doubled quotes, commas and line breaks inside quotes', () => {
    expect(parseCsv('a,"b,c","d ""e""","f\r\ng"\r\n1,2,3,4')).toEqual([
      ['a', 'b,c', 'd "e"', 'f\ng'],
      ['1', '2', '3', '4'],
    ]);
  });

  it('drops a byte order mark and empty lines, keeps empty cells', () => {
    expect(parseCsv('\uFEFFa,b\n\n,\n"",x\n')).toEqual([
      ['a', 'b'],
      ['', 'x'],
    ]);
  });

  it('takes a stray quote inside a cell as it is, and ends without a final line break', () => {
    expect(parseCsv('say "hi",b\nc,"d"')).toEqual([
      ['say "hi"', 'b'],
      ['c', 'd'],
    ]);
  });

  it('finds columns without regard to case and lists the rest', () => {
    const table = new CsvTable('Name,URL,Extra\nx,https://example.com,y\n');
    const row = table.rows[0]!;
    expect(table.has('name', 'url')).toBe(true);
    expect(table.get(row, 'missing', 'url')).toBe('https://example.com');
    expect(table.rest(row, ['name', 'url'])).toEqual([['Extra', 'y']]);
  });
});
