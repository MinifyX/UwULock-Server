import { useEffect, useState } from 'react';
import { errorText } from '../../lib/errors';
import {
  STATUS,
  families,
  setItemCollections,
  shareItem,
  writableCollections,
  type CollectionDetails,
} from '../../lib/families';
import { t, useLanguage } from '../../lib/i18n';
import { toast } from '../../lib/toast';
import { Modal } from '../Modal';

/** The families the account is confirmed in: where it can share items. */
export const shareTargets = () => families().filter((f) => f.status === STATUS.confirmed);

/**
 * Move a personal item into a family (`organizationId` null), or change which of a family's
 * collections an item is in. Moving encrypts the item anew under the family's key; from then on
 * it belongs to the family, not to the account.
 */
export function ShareToFamily({
  itemId,
  itemName,
  organizationId,
  collectionIds,
  onClose,
}: {
  itemId: string;
  itemName: string;
  organizationId: string | null;
  collectionIds: string[];
  onClose: () => void;
}) {
  useLanguage();
  const targets = shareTargets();
  const [orgId, setOrgId] = useState(organizationId ?? targets[0]?.id ?? '');
  const [collections, setCollections] = useState<CollectionDetails[] | null>(null);
  const [chosen, setChosen] = useState<Set<string>>(new Set(collectionIds));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!orgId) return;
    setCollections(null);
    writableCollections(orgId).then(setCollections, (e) => setError(errorText(e)));
  }, [orgId]);

  const moving = organizationId === null;
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      if (moving) {
        await shareItem(itemId, orgId, [...chosen]);
        toast(t('In die Familie verschoben ✧'));
      } else {
        await setItemCollections(itemId, [...chosen]);
        toast(t('Gespeichert ✧'));
      }
      onClose();
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  return (
    <Modal
      title={moving ? t('In eine Familie verschieben') : t('Sammlungen')}
      onCancel={() => !busy && onClose()}
      footer={
        <>
          <span className="spacer" />
          <button data-secondary onClick={onClose} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button
            className="primary"
            disabled={busy || !orgId || chosen.size === 0}
            onClick={() => void submit()}
          >
            {moving ? t('Verschieben') : t('Speichern')}
          </button>
        </>
      }
    >
      <div className="form">
        {moving && (
          <p className="dialog-lead">
            {t(
              '„{name}“ gehört danach der Familie: Wer die gewählten Sammlungen sieht, sieht den Eintrag, und aus deinem eigenen Tresor verschwindet er. Zurück geht es nur als Kopie.',
              { name: itemName },
            )}
          </p>
        )}
        {moving && targets.length > 1 && (
          <label className="field">
            <span>{t('Familie')}</span>
            <select
              className="select"
              value={orgId}
              onChange={(e) => {
                setOrgId(e.target.value);
                setChosen(new Set());
              }}
            >
              {targets.map((family) => (
                <option key={family.id} value={family.id}>
                  {family.name}
                </option>
              ))}
            </select>
          </label>
        )}
        <fieldset className="field">
          <legend>{t('Sammlungen')}</legend>
          {collections === null ? (
            <p className="detail-line">{t('Einen Moment …')}</p>
          ) : collections.length === 0 ? (
            <p className="detail-line">
              {t('In dieser Familie darfst du in keine Sammlung etwas legen.')}
            </p>
          ) : (
            collections.map((collection) => (
              <label key={collection.id} className="check">
                <input
                  type="checkbox"
                  checked={chosen.has(collection.id)}
                  onChange={(e) => {
                    const next = new Set(chosen);
                    if (e.target.checked) next.add(collection.id);
                    else next.delete(collection.id);
                    setChosen(next);
                  }}
                />
                {collection.name}
              </label>
            ))
          )}
        </fieldset>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </div>
    </Modal>
  );
}
