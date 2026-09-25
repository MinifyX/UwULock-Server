// After `vite build`: a .br and a .gz copy of every file that shrinks, compressed as hard as the
// formats go. The server embeds them and hands out whichever a browser takes, so nothing is
// compressed again per request.

import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { brotliCompressSync, constants, gzipSync } from 'node:zlib';

const dist = join(dirname(fileURLToPath(import.meta.url)), '../dist');
const shrinks = /\.(html|js|mjs|css|json|svg|wasm|webmanifest|txt)$/;

const files = (dir) =>
  readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : [path];
  });

let before = 0;
let after = 0;
for (const file of files(dist).filter((file) => shrinks.test(file))) {
  const bytes = readFileSync(file);
  const brotli = brotliCompressSync(bytes, {
    params: {
      [constants.BROTLI_PARAM_QUALITY]: constants.BROTLI_MAX_QUALITY,
      [constants.BROTLI_PARAM_SIZE_HINT]: bytes.length,
    },
  });
  const gzip = gzipSync(bytes, { level: 9 });
  // Only worth it when it is smaller.
  if (brotli.length < bytes.length) writeFileSync(`${file}.br`, brotli);
  if (gzip.length < bytes.length) writeFileSync(`${file}.gz`, gzip);
  before += bytes.length;
  after += Math.min(brotli.length, bytes.length);
}
console.log(
  `compressed ${Math.round(before / 1024)} KiB to ${Math.round(after / 1024)} KiB (brotli)`,
);
