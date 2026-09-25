/**
 * Where on the page we are, from the part after `#`: `#/finish-signup?token=…&email=…` is the
 * link from an invitation mail. Bitwarden's web vault uses the same paths, so links the official
 * clients make lead to the right place here too.
 */

import { useSyncExternalStore } from 'react';

export type Route = { path: string; query: URLSearchParams };

function parse(hash: string): Route {
  const [path = '', query = ''] = hash.replace(/^#/, '').split('?');
  return { path: path || '/', query: new URLSearchParams(query) };
}

let current = parse(location.hash);
const listeners = new Set<() => void>();

window.addEventListener('hashchange', () => {
  current = parse(location.hash);
  for (const listener of listeners) listener();
});

export function useRoute(): Route {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => current,
  );
}

export function go(path: string) {
  location.hash = path;
}
