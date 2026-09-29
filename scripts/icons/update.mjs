#!/usr/bin/env node
// The icon databases that come with the server (docs/icons.md): fetches their upstream
// repositories at the commits in crates/uwulock-server/icon-databases/sources.json, makes the
// packs with `uwulock-server icon-databases`, and checks them against SHA256SUMS next to them.
//
//   node scripts/icons/update.mjs           the pinned commits again: fails when a pack comes out
//                                           other than SHA256SUMS says (nothing is written then)
//   node scripts/icons/update.mjs --bump    each repository's newest commit: writes the packs,
//                                           sources.json and SHA256SUMS
//   node scripts/icons/update.mjs --write   the pinned commits, and SHA256SUMS written anew (after
//                                           a change to how the packs are made)
//
// Needs git, cargo and the network; only the repositories' paths that are used are fetched, with
// git's own checks of every object. CI does not run it: the packs are committed.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const dir = join(root, 'crates', 'uwulock-server', 'icon-databases');
const mode = process.argv[2] ?? 'check';
if (!['check', '--bump', '--write'].includes(mode)) {
  console.error('usage: update.mjs [--bump | --write]');
  process.exit(2);
}

const git = (args, cwd) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }).trim();
const sha256 = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');

const sources = JSON.parse(readFileSync(join(dir, 'sources.json'), 'utf8'));
const work = mkdtempSync(join(tmpdir(), 'uwulock-icons-'));
try {
  for (const [id, source] of Object.entries(sources)) {
    if (mode === '--bump') {
      source.commit = git(['ls-remote', source.repository, 'HEAD']).split(/\s/)[0];
    }
    if (!/^[0-9a-f]{40}$/.test(source.commit)) throw new Error(`${id}: no commit`);
    const checkout = join(work, id);
    git(['init', '-q', checkout]);
    git(['remote', 'add', 'origin', source.repository], checkout);
    git(['fetch', '-q', '--depth', '1', '--filter=blob:none', 'origin', source.commit], checkout);
    git(['sparse-checkout', 'set', '--no-cone', ...source.paths.map((path) => `/${path}`)], checkout);
    git(['-c', 'advice.detachedHead=false', 'checkout', '-q', 'FETCH_HEAD'], checkout);
    const head = git(['rev-parse', 'HEAD'], checkout);
    if (head !== source.commit) throw new Error(`${id}: got ${head}, not ${source.commit}`);
    console.log(`${id}: ${source.repository} at ${head}`);
  }

  // The packs are made into a directory of their own, so a check leaves the committed ones alone.
  const out = join(work, 'out');
  execFileSync('mkdir', ['-p', out]);
  writeFileSync(join(out, 'sources.json'), `${JSON.stringify(sources, null, 2)}\n`);
  for (const id of Object.keys(sources)) {
    // The binary includes the packs: a missing one would stop it from being built at all.
    if (!existsSync(join(dir, `${id}.pack`))) writeFileSync(join(dir, `${id}.pack`), '');
  }
  execFileSync(
    'cargo',
    ['run', '-q', '--release', '--locked', '-p', 'uwulock-server', '--', 'icon-databases', '--upstream', work, '--out', out],
    { cwd: root, stdio: ['ignore', 'inherit', 'inherit'], env: { ...process.env, RUST_LOG: 'error' } },
  );

  const sums = Object.keys(sources)
    .sort()
    .map((id) => `${sha256(join(out, `${id}.pack`))}  ${id}.pack`)
    .join('\n');
  if (mode === 'check') {
    const committed = readFileSync(join(dir, 'SHA256SUMS'), 'utf8').trim();
    const packs = Object.keys(sources).map((id) => `${sha256(join(dir, `${id}.pack`))}  ${id}.pack`).sort().join('\n');
    if (sums !== committed || packs !== committed) {
      console.error(`The packs differ from SHA256SUMS:\nmade:\n${sums}\ncommitted:\n${committed}\non disk:\n${packs}`);
      process.exit(1);
    }
    console.log('The packs are what SHA256SUMS says, and what the pinned commits make.');
  } else {
    for (const id of Object.keys(sources)) copyFileSync(join(out, `${id}.pack`), join(dir, `${id}.pack`));
    writeFileSync(join(dir, 'sources.json'), `${JSON.stringify(sources, null, 2)}\n`);
    writeFileSync(join(dir, 'SHA256SUMS'), `${sums}\n`);
    console.log(`Written to ${dir}. Commit the packs, sources.json and SHA256SUMS together.`);
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}
