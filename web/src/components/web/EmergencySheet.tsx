import { useState, type FormEvent } from 'react';
import { recoveryCode } from '../../lib/account';
import { errorText } from '../../lib/errors';
import { EMERGENCY_STATUS, trustedContacts } from '../../lib/features';
import { language, t, useLanguage } from '../../lib/i18n';
import { emergencySheet, type SheetLanguage } from '../../lib/sheet';
import { toast } from '../../lib/toast';
import { currentSession } from '../../lib/web/http';
import { Modal } from '../Modal';
import { PasswordInput } from '../PasswordInput';
import { Segmented, save } from './controls';

/**
 * The emergency sheet, made here in the browser: after the master password (for the recovery
 * code of two-step login), a PDF to print and keep safe. The server never sees it.
 */
export function EmergencySheetDialog({ onClose }: { onClose: () => void }) {
  useLanguage();
  const [password, setPassword] = useState('');
  const [sheetLanguage, setSheetLanguage] = useState<SheetLanguage>(
    language() === 'en' ? 'en' : 'de',
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const make = async (event?: FormEvent) => {
    event?.preventDefault();
    if (!password || busy) return;
    setBusy(true);
    setError(null);
    try {
      const [{ code }, contacts] = await Promise.all([recoveryCode(password), trustedContacts()]);
      const pdf = emergencySheet({
        server: location.origin,
        email: currentSession()?.email ?? '',
        recoveryCode: code,
        contacts: contacts
          .filter((contact) => contact.status >= EMERGENCY_STATUS.confirmed)
          .map((contact) => ({
            name: contact.name,
            email: contact.email,
            type: contact.type,
            waitTimeDays: contact.waitTimeDays,
          })),
        language: sheetLanguage,
        date: new Date(),
      });
      save(
        new Blob([pdf as BlobPart], { type: 'application/pdf' }),
        sheetLanguage === 'de' ? 'uwulock-notfallblatt.pdf' : 'uwulock-emergency-sheet.pdf',
      );
      toast(t('Notfallblatt erstellt ✧ Druck es aus und lösch die Datei danach.'));
      onClose();
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  return (
    <Modal
      title={t('Notfallblatt erstellen')}
      tone="warning"
      onCancel={() => !busy && onClose()}
      footer={
        <>
          <span className="spacer" />
          <button data-secondary onClick={onClose} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button className="primary" disabled={busy || !password} onClick={() => void make()}>
            {busy ? t('Einen Moment …') : t('PDF erstellen')}
          </button>
        </>
      }
    >
      <form className="form" onSubmit={(event) => void make(event)}>
        <p className="dialog-lead">
          {t(
            'Ein Blatt für deine Angehörigen: Server-Adresse und E-Mail als Text und QR-Code, ein leeres Feld für das Master-Passwort zum Eintragen von Hand, der Wiederherstellungscode der Zwei-Schritt-Anmeldung und eine kurze Anleitung mit deinen Notfallkontakten. Es entsteht hier im Browser, der Server sieht es nie. Wer es hat, kommt mit deinem Master-Passwort an alles: Druck es aus und lösch die Datei danach.',
          )}
        </p>
        <div className="field">
          <span>{t('Sprache des Blatts')}</span>
          <Segmented
            label={t('Sprache des Blatts')}
            value={sheetLanguage}
            onChange={setSheetLanguage}
            options={[
              { value: 'de', label: 'Deutsch' },
              { value: 'en', label: 'English' },
            ]}
          />
        </div>
        <label className="field">
          <span>{t('Master-Passwort')}</span>
          <PasswordInput value={password} onChange={setPassword} autoFocus disabled={busy} />
          <small className="field-hint">
            {t(
              'Für den Wiederherstellungscode. Das Master-Passwort selbst kommt nicht aufs Blatt.',
            )}
          </small>
        </label>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </form>
    </Modal>
  );
}
