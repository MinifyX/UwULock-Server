import type { ReactNode } from 'react';
import { t } from '../lib/i18n';
import { Nyu, type NyuMood } from './nyu/Nyu';
import { NyuScene, type SceneName } from './nyu/scenes';

/**
 * Waiting for the vault, the server or the admin portal: Nyu carries the plug over. Appears only
 * after a moment (`nyu-delayed`), so a quick load shows nothing at all. Nyu is decoration; the
 * text is the status screen readers hear.
 */
export function NyuLoading({ text, scene = 'connecting' }: { text?: string; scene?: SceneName }) {
  return (
    <div className="nyu-loading nyu-delayed" role="status">
      <NyuScene name={scene} className="empty-scene" />
      <p>{text ?? t('Lädt …')}</p>
    </div>
  );
}

/**
 * "Nothing here yet" in a list of a settings page or the admin portal: the text with a small,
 * sleepy Nyu in front. The text stays a paragraph of its own for screen readers.
 */
export function EmptyNote({ children, mood = 'sleepy' }: { children: ReactNode; mood?: NyuMood }) {
  return (
    <div className="empty-note nyu-note">
      <Nyu size={36} mood={mood} blink={false} title="" />
      <p>{children}</p>
    </div>
  );
}
