/**
 * Short notes at the bottom of the window: "Copied", "Synced". One at a time;
 * a new one replaces the old.
 */

import { useSyncExternalStore } from 'react';

export type Toast = { id: number; text: string; tone: 'info' | 'error' };

let current: Toast | null = null;
let counter = 0;
let timer: number | undefined;
const listeners = new Set<() => void>();

function set(next: Toast | null) {
  current = next;
  for (const listener of listeners) listener();
}

export function toast(text: string, tone: Toast['tone'] = 'info') {
  window.clearTimeout(timer);
  set({ id: ++counter, text, tone });
  timer = window.setTimeout(() => set(null), tone === 'error' ? 6000 : 2600);
}

export function useToast(): Toast | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => current,
  );
}
