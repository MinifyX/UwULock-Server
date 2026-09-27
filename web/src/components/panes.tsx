import { createContext, useContext } from 'react';
import { t, useLanguage } from '../lib/i18n';
import { Icon } from './Icon';

/**
 * On a phone the vault shows one layer at a time — the list, or what is picked in it — and a
 * pane that opens something says so here. On a wide screen both are there anyway, and this does
 * nothing anybody sees.
 */
export const Panes = createContext<{ showDetail: () => void; back: () => void }>({
  showDetail: () => undefined,
  back: () => undefined,
});

/** Back to the list; only on narrow screens. */
export function BackToList() {
  useLanguage();
  const { back } = useContext(Panes);
  return (
    <button type="button" className="pane-back quiet" onClick={back}>
      <Icon name="chevron" size={15} />
      {t('Zurück')}
    </button>
  );
}
