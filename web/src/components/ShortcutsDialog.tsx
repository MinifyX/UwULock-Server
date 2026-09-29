import { Fragment } from 'react';
import { t, useLanguage } from '../lib/i18n';
import { updateSettings, useSettings } from '../lib/settings';
import { type ShortcutGroup } from '../lib/shortcuts';
import { Modal } from './Modal';
import { Toggle } from './web/controls';

/** The overview of the keyboard shortcuts, behind `?` and the keyboard button in the bar. */
export function ShortcutsDialog({
  groups,
  onClose,
}: {
  groups: ShortcutGroup[];
  onClose: () => void;
}) {
  useLanguage();
  const settings = useSettings();
  return (
    <Modal
      title={t('Tastenkürzel')}
      onCancel={onClose}
      footer={
        <>
          <span className="spacer" />
          <button className="primary" onClick={onClose}>
            {t('Schließen')}
          </button>
        </>
      }
    >
      {/* Focus starts at the top of the list, so the dialog opens at its beginning; Tab goes on
          to the switch and the button. */}
      <div className="shortcuts" tabIndex={-1} data-autofocus>
        {groups.map((group) => (
          <table key={group.title} className="shortcut-table">
            <caption>{t(group.title)}</caption>
            <thead className="sr-only">
              <tr>
                <th scope="col">{t('Tasten')}</th>
                <th scope="col">{t('Wirkung')}</th>
              </tr>
            </thead>
            <tbody>
              {group.shortcuts.map((shortcut) => (
                <tr
                  key={shortcut.label + shortcut.keys.join()}
                  data-off={(shortcut.single && !settings.singleKeys) || undefined}
                >
                  <td className="shortcut-keys">
                    {shortcut.keys.map((chord, index) => (
                      <Fragment key={chord.join('+')}>
                        {index > 0 && <span className="shortcut-or"> / </span>}
                        {chord.map((key, at) => (
                          <Fragment key={key}>
                            {at > 0 && '+'}
                            <kbd>{t(key)}</kbd>
                          </Fragment>
                        ))}
                      </Fragment>
                    ))}
                  </td>
                  <th scope="row">
                    {t(shortcut.label)}
                    {shortcut.single && !settings.singleKeys && (
                      <span className="shortcut-off"> {t('(ausgeschaltet)')}</span>
                    )}
                  </th>
                </tr>
              ))}
            </tbody>
          </table>
        ))}
        <div className="shortcut-single">
          <div className="setting-text">
            <p className="setting-label">{t('Kürzel mit einer Taste')}</p>
            <p className="setting-description">
              {t(
                'Wirken nur außerhalb von Textfeldern. Schalte sie aus, wenn sie deiner Spracheingabe oder deinem Screenreader in die Quere kommen.',
              )}
            </p>
          </div>
          <Toggle
            label={t('Kürzel mit einer Taste')}
            checked={settings.singleKeys}
            onChange={(singleKeys) => updateSettings({ singleKeys })}
          />
        </div>
      </div>
    </Modal>
  );
}
