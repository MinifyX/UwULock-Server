import { useEffect, useRef, useState } from 'react';
import { Button, Icon, IconButton, ICONS } from '@uwusuite/design';
import { errorText } from '../../lib/errors';
import {
  addAttachment,
  attachmentsOf,
  deleteAttachment,
  downloadAttachment,
  type Attachment,
} from '../../lib/features';
import { bytes } from '../../lib/format';
import { t, useLanguage } from '../../lib/i18n';
import { toast } from '../../lib/toast';
import { Modal } from '../Modal';
import { save } from './controls';

/**
 * An item's files: each encrypted in the browser before it goes up, and opened in the browser
 * when it comes down. The server keeps them as it got them.
 */
export function Attachments({
  itemId,
  revision,
  editable,
}: {
  itemId: string;
  /** Changes when the item does, so the list is read again. */
  revision: string | null;
  editable: boolean;
}) {
  useLanguage();
  const [list, setList] = useState<Attachment[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<Attachment | null>(null);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    attachmentsOf(itemId).then(setList, () => setList([]));
  }, [itemId, revision]);

  const add = async (file: File) => {
    setBusy(t('Verschlüsselt und lädt „{name}“ hoch …', { name: file.name }));
    try {
      await addAttachment(itemId, file);
      toast(t('Angehängt ✧'));
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setBusy(null);
      if (input.current) input.current.value = '';
    }
  };

  const open = async (attachment: Attachment) => {
    setBusy(t('Lädt und entschlüsselt „{name}“ …', { name: attachment.fileName }));
    try {
      save(await downloadAttachment(itemId, attachment.id), attachment.fileName);
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setBusy(null);
    }
  };

  const remove = async (attachment: Attachment) => {
    setDeleting(null);
    setBusy(t('Löscht …'));
    try {
      await deleteAttachment(itemId, attachment.id);
      toast(t('Anhang gelöscht.'));
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setBusy(null);
    }
  };

  if (!list.length && !editable) return null;
  return (
    <section className="detail-card">
      <h3 className="detail-card-title">{t('Anhänge')}</h3>
      {list.map((attachment) => (
        <div className="detail-row" key={attachment.id}>
          <div className="detail-text">
            <span className="detail-value attachment-name">
              <Icon icon={ICONS.file} size="xs" />
              {attachment.fileName}
            </span>
            <span className="detail-label">{bytes(attachment.size)}</span>
          </div>
          <div className="detail-actions">
            <IconButton
              icon={ICONS.download}
              label={t('{name} herunterladen', { name: attachment.fileName })}
              disabled={Boolean(busy)}
              onClick={() => void open(attachment)}
            />
            {editable && (
              <IconButton
                icon={ICONS.delete}
                label={t('{name} löschen', { name: attachment.fileName })}
                disabled={Boolean(busy)}
                onClick={() => setDeleting(attachment)}
              />
            )}
          </div>
        </div>
      ))}
      {busy && (
        <p className="field-hint" role="status">
          {busy}
        </p>
      )}
      {editable && (
        <div className="attachment-add">
          <input
            ref={input}
            type="file"
            hidden
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void add(file);
            }}
          />
          <Button
            variant="ghost"
            disabled={Boolean(busy)}
            onClick={() => input.current?.click()}
            icon={ICONS.attachment}
          >
            {t('Datei anhängen …')}
          </Button>
        </div>
      )}
      {deleting && (
        <Modal
          title={t('Anhang löschen?')}
          tone="warning"
          onCancel={() => setDeleting(null)}
          footer={
            <>
              <span className="spacer" />
              <Button data-secondary onClick={() => setDeleting(null)}>
                {t('Abbrechen')}
              </Button>
              <Button variant="danger" onClick={() => void remove(deleting)}>
                {t('Löschen')}
              </Button>
            </>
          }
        >
          <p className="dialog-lead">
            {t('„{name}“ ist danach weg, auf jedem Gerät.', { name: deleting.fileName })}
          </p>
        </Modal>
      )}
    </section>
  );
}
