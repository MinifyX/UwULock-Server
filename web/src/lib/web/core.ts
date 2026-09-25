/**
 * The crypto and the vault, in WebAssembly (web/wasm). Loaded once; every call goes through
 * here, which turns its JSON back into objects and its errors into `{ kind, message }`.
 */

import init, * as wasm from '../../wasm/pkg/core.js';
import wasmUrl from '../../wasm/pkg/core_bg.wasm?url';

let ready: Promise<unknown> | null = null;

/** Load the module; every function below waits for this first. */
export function load(): Promise<unknown> {
  ready ??= init({ module_or_path: wasmUrl });
  return ready;
}

export type Failure = { kind: string; message: string };

function failure(error: unknown): Failure {
  if (typeof error === 'string') {
    try {
      const parsed = JSON.parse(error) as Failure;
      if (parsed && typeof parsed.kind === 'string') return parsed;
    } catch {
      // Not ours: a plain message.
    }
    return { kind: 'crypto', message: error };
  }
  if (error instanceof Error) return { kind: 'crypto', message: error.message };
  return { kind: 'unknown', message: String(error) };
}

/** Call into the module; throws a `Failure`. */
export async function call<T>(work: (core: typeof wasm) => T): Promise<T> {
  await load();
  try {
    return work(wasm);
  } catch (error) {
    throw failure(error);
  }
}

/** The same, for calls that answer JSON. */
export async function callJson<T>(work: (core: typeof wasm) => string): Promise<T> {
  return JSON.parse(await call(work)) as T;
}
