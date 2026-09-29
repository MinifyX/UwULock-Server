import { useCallback, useEffect, useState } from 'react';
import { PasswordPrompt } from '../components/web/controls';
import { deleteOrganization, organizations, type AdminOrganization } from '../lib/admin';
import { errorText } from '../lib/errors';
import { when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';

/**
 * The families on the server (and Stufe 5's organisations): their names, owners and how many
 * are in them — nothing of what they share. An admin can delete one, for example when its only
 * owner is gone.
 */
export function Families() {
  useLanguage();
  const [list, setList] = useState<AdminOrganization[] | null>(null);
  const [deleting, setDeleting] = useState<AdminOrganization | null>(null);
  const load = useCallback(() => {
    organizations().then(setList, (e) => toast(errorText(e), 'error'));
  }, []);
  useEffect(load, [load]);

  return (
    <>
      <p className="settings-lead">
        {t(
          'Familien teilen Einträge in Sammlungen, verschlüsselt mit einem eigenen Schlüssel. Wer eine anlegen darf und wie groß sie wird, steht unter Einstellungen. Was darin liegt, sieht hier niemand.',
        )}
      </p>
      <table className="admin-table">
        <thead>
          <tr>
            <th>{t('Name')}</th>
            <th>{t('Art')}</th>
            <th>{t('Eigentümer')}</th>
            <th>{t('Mitglieder')}</th>
            <th>{t('Angelegt')}</th>
            <th aria-label={t('Aktionen')} />
          </tr>
        </thead>
        <tbody>
          {list?.map((org) => (
            <tr key={org.id}>
              <td>{org.name}</td>
              <td>{org.kind === 'family' ? t('Familie') : t('Organisation')}</td>
              <td>{org.owners.join(', ') || '–'}</td>
              <td>{org.members}</td>
              <td>{when(org.creationDate) ?? ''}</td>
              <td>
                <button className="quiet danger-text" onClick={() => setDeleting(org)}>
                  {t('Löschen')}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {list?.length === 0 && <p className="empty-note">{t('Noch keine Familien.')}</p>}
      {deleting && (
        <PasswordPrompt
          title={t('Familie löschen?')}
          tone="warning"
          lead={t(
            '„{name}“ verschwindet für alle Mitglieder, mit allen Sammlungen und allen Einträgen darin. Das lässt sich nicht rückgängig machen.',
            { name: deleting.name },
          )}
          confirm={t('Familie löschen')}
          onCancel={() => setDeleting(null)}
          action={async (password) => {
            await deleteOrganization(deleting.id, password);
            setDeleting(null);
            toast(t('Gelöscht.'));
            load();
          }}
        />
      )}
    </>
  );
}
