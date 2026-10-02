import { useCallback, useEffect, useState } from 'react';
import { Button, Section, Table } from '../components/ui';
import { PasswordPrompt } from '../components/web/controls';
import { deleteOrganization, organizations, type AdminOrganization } from '../lib/admin';
import { errorText } from '../lib/errors';
import { when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import { EmptyNote } from '../components/NyuStates';

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
      <Section
        heading={t('Familien auf diesem Server')}
        lead={t(
          'Familien teilen Einträge in Sammlungen, verschlüsselt mit einem eigenen Schlüssel. Was darin liegt, sieht hier niemand.',
        )}
      >
        {list?.length === 0 ? (
          <EmptyNote>{t('Noch keine Familien.')}</EmptyNote>
        ) : (
          <Table
            label={t('Familien')}
            head={
              <>
                <th>{t('Name')}</th>
                <th>{t('Art')}</th>
                <th>{t('Eigentümer')}</th>
                <th>{t('Mitglieder')}</th>
                <th>{t('Angelegt')}</th>
                <th>
                  <span className="sr-only">{t('Aktionen')}</span>
                </th>
              </>
            }
          >
            {list?.map((org) => (
              <tr key={org.id}>
                <td>{org.name}</td>
                <td>{org.kind === 'family' ? t('Familie') : t('Organisation')}</td>
                <td>{org.owners.join(', ') || '–'}</td>
                <td>{org.members}</td>
                <td>{when(org.creationDate) ?? ''}</td>
                <td className="row-actions">
                  <Button size="small" variant="quiet-danger" onClick={() => setDeleting(org)}>
                    {t('Löschen …')}
                    <span className="sr-only">{org.name}</span>
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Section>
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
