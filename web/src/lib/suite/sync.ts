/**
 * The suite vault's spaces in the web vault (docs/uwu-api.md §6): open a space with the extras
 * key, pull its records page by page, seal and push changes by the apps' rules, and keep the
 * page's view of it current — also when an app changes something (the realtime channel, §5).
 *
 * The keys and the sealed records stay in the WebAssembly module; this file moves envelopes
 * between it and the server and tells the page what changed.
 */

import { useEffect, useState } from 'react';
import type { Status } from '../api';
import { errorCode } from '../errors';
import { listen } from '../events';
import { openExtras } from '../requests';
import { call, callJson } from '../web/core';
import { ApiError, currentSession, request } from '../web/http';
import type { Payload, SpaceName, SuiteRecord } from './model';
import { watchSuite } from './live';

export type SpaceState =
  | { status: 'loading' }
  /** The suite vault is switched off on this server. */
  | { status: 'off' }
  /** No app made the space yet. */
  | { status: 'none' }
  /** The extras key of the account doesn't open any more. */
  | { status: 'lost' }
  | { status: 'error'; error: unknown }
  | { status: 'open'; records: SuiteRecord[]; unreadable: number };

type Envelope = { id: string; kind: string; [key: string]: unknown };
type Listed = { space: string; id: string; key: string };
type Pull = { reset: boolean; records: Envelope[]; cursor: number; hasMore: boolean };
type Pushed = { accepted: { id: string; seq: number }[]; conflicts: Envelope[]; cursor: number };

const states = new Map<SpaceName, SpaceState>();
const cursors = new Map<SpaceName, number>();
const listeners = new Map<SpaceName, Set<(state: SpaceState) => void>>();
/** One load or pull of a space at a time; later ones wait for it. */
const running = new Map<SpaceName, Promise<void>>();

function set(space: SpaceName, state: SpaceState) {
  states.set(space, state);
  for (const listener of listeners.get(space) ?? []) listener(state);
}

export function stateOf(space: SpaceName): SpaceState {
  return states.get(space) ?? { status: 'loading' };
}

/** Everything of every space forgotten: the vault locked, or another account. */
export function forgetSuite() {
  states.clear();
  cursors.clear();
  spaceIds.clear();
}

let account: string | null = null;
void listen<Status>('vault-status', ({ payload }) => {
  const now = payload.state === 'unlocked' ? payload.accountId : null;
  if (now === account) return;
  account = now;
  forgetSuite();
  // A space on screen is read again for the account now open.
  for (const [space, set] of listeners) {
    if (!set.size) continue;
    set.forEach((listener) => listener({ status: 'loading' }));
    if (now) void loadSpace(space);
  }
});

const DEVICE_KEY = 'uwulock.suite.device.';
let sessionDevice: number | null = null;

function randomDevice(): number {
  const one = new Uint32Array(1);
  do crypto.getRandomValues(one);
  while (one[0] === 0);
  return one[0]!;
}

/**
 * This browser's device id in the records' clocks (`updatedAt.device`): random, never 0, kept
 * per browser and account. Without local storage (a private window) one per page load.
 */
export function suiteDevice(account = currentSession()?.email ?? ''): number {
  try {
    const key = DEVICE_KEY + account.toLowerCase();
    const kept = Number(window.localStorage.getItem(key));
    if (Number.isInteger(kept) && kept > 0 && kept <= 0xffff_ffff) return kept;
    const made = randomDevice();
    window.localStorage.setItem(key, String(made));
    return made;
  } catch {
    sessionDevice ??= randomDevice();
    return sessionDevice;
  }
}

const recordsPath = (space: SpaceName) =>
  `/uwu/v1/suite/spaces/${encodeURIComponent(space)}/records`;

/** What the module shows of a space now. */
async function show(space: SpaceName) {
  const shown = await callJson<{ records: SuiteRecord[]; unreadable: number }>((core) =>
    core.suiteRecords(space),
  );
  set(space, { status: 'open', ...shown });
}

/** A server that keeps a pull going without getting anywhere. */
const stuck = () => ({ kind: 'server', message: 'The server’s pull of this space goes nowhere.' });

/**
 * Pull from the cursor until there is no more; from 0 again when the server says `reset`. A
 * server that says `reset` again right after one, or `hasMore` without moving the cursor on,
 * is stopped there instead of being asked forever.
 */
async function pullAll(space: SpaceName) {
  let resetJustNow = false;
  for (let round = 0; ; round++) {
    if (round >= 10_000) throw stuck();
    const since = cursors.get(space) ?? 0;
    const page = await request<Pull>(`${recordsPath(space)}?since=${since}&limit=500`);
    if (page.reset) {
      if (resetJustNow) throw stuck();
      resetJustNow = true;
      await call((core) => core.suiteForgetRecords(space));
      cursors.set(space, 0);
      continue;
    }
    resetJustNow = false;
    if (!Array.isArray(page.records) || !Number.isSafeInteger(page.cursor)) throw stuck();
    if (page.records.length)
      await call((core) => core.suiteMerge(space, JSON.stringify(page.records)));
    if (page.hasMore && page.cursor <= since) throw stuck();
    cursors.set(space, page.cursor);
    if (!page.hasMore) break;
  }
  await show(space);
}

function once(space: SpaceName, work: () => Promise<void>): Promise<void> {
  const before = running.get(space) ?? Promise.resolve();
  const next = before.catch(() => undefined).then(work);
  running.set(space, next);
  return next;
}

/** Open the space (its key from the list of spaces) and read everything new. */
async function open(space: SpaceName, fresh: boolean) {
  try {
    await openExtras();
  } catch (error) {
    if ((error as { kind?: string })?.kind === 'extras-lost') return set(space, { status: 'lost' });
    throw error;
  }
  let listed: Listed[];
  try {
    listed = (await request<{ data: Listed[] }>('/uwu/v1/suite/spaces')).data;
  } catch (error) {
    if (errorCode(error) === 'feature_off') return set(space, { status: 'off' });
    throw error;
  }
  const found = listed.find((s) => s.space === space);
  if (!found) {
    cursors.delete(space);
    return set(space, { status: 'none' });
  }
  const opened = await callJson<{ id: string }>((core) =>
    core.suiteOpenSpace(JSON.stringify(found)),
  );
  if (fresh || opened.id !== spaceIds.get(space)) {
    // Another space than the one read (a rekey), or asked to start over.
    await call((core) => core.suiteForgetRecords(space));
    cursors.set(space, 0);
  }
  spaceIds.set(space, opened.id);
  await pullAll(space);
}

const spaceIds = new Map<SpaceName, string>();

/** Load a space: open it the first time, then only pull what is new. */
export function loadSpace(space: SpaceName, fresh = false): Promise<void> {
  return once(space, async () => {
    try {
      if (!fresh && stateOf(space).status === 'open') await pullAll(space);
      else await open(space, fresh);
    } catch (error) {
      set(space, { status: 'error', error });
    }
  });
}

/**
 * Make the space when no app did yet: a fresh key under the extras key. When another device was
 * quicker (409 `exists`), take its space.
 */
export function createSpace(space: SpaceName): Promise<void> {
  // In line with loads and pulls of the space: none of them opens the space in the module
  // between the fresh key and the server's answer to it.
  return once(space, async () => {
    await openExtras();
    const body = await callJson<{ id: string; key: string }>((core) =>
      core.suiteCreateSpace(space),
    );
    try {
      await request(`/uwu/v1/suite/spaces/${encodeURIComponent(space)}`, { method: 'PUT', body });
    } catch (error) {
      if (errorCode(error) !== 'exists' && (error as ApiError).status !== 409) throw error;
    }
    try {
      await open(space, true);
    } catch (error) {
      set(space, { status: 'error', error });
    }
  });
}

/** A secret's content: a password, a passphrase, a private key. */
export async function revealSecret(space: SpaceName, id: string): Promise<string> {
  const secret = await callJson<{ text?: string; bytes?: string }>((core) =>
    core.suiteSecret(space, id),
  );
  if (typeof secret.text === 'string') return secret.text;
  throw { kind: 'unsupported', message: 'This secret is not text.' };
}

/** The space was given a new key elsewhere (409 `space_changed`): read again, write again. */
export class SpaceChanged extends Error {}

/**
 * Changes to push together, sealed as they are added: new records (whose ids come back at
 * once, so another record can point at them), edits and tombstones of records as they were
 * read last.
 */
export class Batch {
  private envelopes: Envelope[] = [];
  private readonly device = suiteDevice();

  constructor(private readonly space: SpaceName) {}

  get size() {
    return this.envelopes.length;
  }

  private static wire(payload: Payload | string) {
    return JSON.stringify(typeof payload === 'string' ? { text: payload } : { json: payload });
  }

  /** A new record; its id. A `secret` is text, every other kind JSON. */
  async add(kind: string, payload: Payload | string): Promise<string> {
    const sealed = await callJson<Envelope>((core) =>
      core.suiteSealNew(this.space, kind, Batch.wire(payload), Date.now(), this.device),
    );
    this.envelopes.push(sealed);
    return sealed.id;
  }

  async edit(id: string, payload: Payload | string): Promise<void> {
    this.envelopes.push(
      await callJson<Envelope>((core) =>
        core.suiteSealEdit(this.space, id, Batch.wire(payload), Date.now(), this.device),
      ),
    );
  }

  async remove(id: string): Promise<void> {
    this.envelopes.push(
      await callJson<Envelope>((core) =>
        core.suiteSealTombstone(this.space, id, Date.now(), this.device),
      ),
    );
  }

  /**
   * Push it all, in one transaction. Answers the ids that changed elsewhere meanwhile: those
   * were not written, and the space now shows the server's version of them.
   */
  async push(): Promise<string[]> {
    const space = this.space;
    if (!this.envelopes.length) return [];
    const pushed = JSON.stringify(this.envelopes);
    const body = await callJson<unknown>((core) => core.suitePushRequest(space, pushed));
    let answer: Pushed;
    try {
      answer = await request<Pushed>(recordsPath(space), { body });
    } catch (error) {
      if (errorCode(error) === 'space_changed') {
        await loadSpace(space, true);
        throw new SpaceChanged('space_changed');
      }
      throw error;
    }
    const conflicts = await callJson<string[]>((core) =>
      core.suiteApplyPush(space, pushed, JSON.stringify(answer)),
    );
    this.envelopes = [];
    await show(space);
    // What else changed in between, from the cursor on.
    void loadSpace(space);
    return conflicts;
  }
}

/** A space's state for a component, loaded on first use and kept current while it is shown. */
export function useSuiteSpace(space: SpaceName, on: boolean): SpaceState {
  const [state, setState] = useState<SpaceState>(() => stateOf(space));
  useEffect(() => {
    if (!on) return;
    const set = listeners.get(space) ?? new Set();
    listeners.set(space, set);
    set.add(setState);
    setState(stateOf(space));
    void loadSpace(space);
    const stop = watchSuite(space, () => void loadSpace(space));
    return () => {
      set.delete(setState);
      stop();
    };
  }, [space, on]);
  return state;
}
