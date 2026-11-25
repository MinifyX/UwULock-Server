/**
 * Short notes at the bottom of the window: "Copied", "Synced". @uwusuite/design's toasts
 * (`<Toaster store={toasts} />` in App and AdminApp), one at a time — a new one replaces the old —
 * and quicker than the package's default, because most of them answer a click that was just made.
 */

import { createToasts } from '@uwusuite/design';
import { Nyu } from '../components/nyu/Nyu';

export const toasts = createToasts({ infoMs: 2600, errorMs: 6000, max: 1 });

/**
 * A small Nyu at the start: sad for an error, starry-eyed when something worked or was copied
 * (those notes end in ✧), otherwise just happy. Decoration only: screen readers hear the text.
 */
export function toast(text: string, tone: 'info' | 'error' = 'info') {
  const mood = tone === 'error' ? 'sad' : text.includes('✧') ? 'sparkle' : 'happy';
  toasts.show(text, {
    tone,
    icon: (
      <span className="inline-flex nyu-pop" aria-hidden="true">
        <Nyu size={22} mood={mood} blink={false} title="" />
      </span>
    ),
  });
}
