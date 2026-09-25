// Builds the web vault's crypto (web/wasm) for the browser, into src/wasm/pkg:
//
//   node scripts/build-wasm.mjs
//
// Needs the wasm32-unknown-unknown target (rustup target add wasm32-unknown-unknown) and
// wasm-bindgen in the version web/wasm/Cargo.toml pins (cargo install wasm-bindgen-cli
// --version <it>).

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = join(dirname(fileURLToPath(import.meta.url)), '..');
const crate = join(web, 'wasm');
const run = (command, args, cwd) => execFileSync(command, args, { cwd, stdio: 'inherit' });

const pinned = readFileSync(join(crate, 'Cargo.toml'), 'utf8').match(
  /wasm-bindgen = "=([^"]+)"/,
)?.[1];
const installed = execFileSync('wasm-bindgen', ['--version'], { encoding: 'utf8' })
  .trim()
  .split(' ')[1];
if (pinned && installed !== pinned) {
  console.error(`wasm-bindgen ${installed} is installed, but web/wasm needs ${pinned}:`);
  console.error(`  cargo install wasm-bindgen-cli --version ${pinned} --locked`);
  process.exit(1);
}

run('cargo', ['build', '--release', '--locked', '--target', 'wasm32-unknown-unknown'], crate);
run(
  'wasm-bindgen',
  [
    '--target',
    'web',
    '--out-dir',
    join(web, 'src/wasm/pkg'),
    '--out-name',
    'core',
    join(crate, 'target/wasm32-unknown-unknown/release/uwulock_web_core.wasm'),
  ],
  web,
);
