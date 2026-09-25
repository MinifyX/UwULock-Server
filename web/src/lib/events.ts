/**
 * Events inside the page, in the shape the desktop app gets them from Rust (`listen` resolves
 * to a function that stops listening), so the same components work in both.
 *
 * - `vault-status` — the vault's state changed; the payload is the new `Status`.
 * - `vault-changed` — items or folders changed; read them again.
 */

type Listener = (event: { payload: unknown }) => void;

const listeners = new Map<string, Set<Listener>>();

export function listen<T>(
  name: string,
  handler: (event: { payload: T }) => void,
): Promise<() => void> {
  const set = listeners.get(name) ?? new Set<Listener>();
  listeners.set(name, set);
  const listener = handler as Listener;
  set.add(listener);
  return Promise.resolve(() => void set.delete(listener));
}

export function emit(name: string, payload?: unknown) {
  for (const listener of listeners.get(name) ?? []) listener({ payload });
}
