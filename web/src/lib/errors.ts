/**
 * Rust says what went wrong in English, for the log; the page says it in the
 * user's language, by kind. Security errors stay plain: no kaomoji, no Nyu.
 */

import { failure, type Failure } from './api';
import { t } from './i18n';

export function errorText(error: unknown): string {
  const f: Failure = failure(error);
  const m = f.message;
  switch (f.kind) {
    case 'network':
      return t('Der Server ist nicht erreichbar: {reason}', { reason: m });
    case 'refused':
      if (m.includes('https://'))
        return t(
          'Der Server muss per https:// erreichbar sein. Unverschlüsseltes http:// geht nur zu diesem Rechner (localhost).',
        );
      if (m.includes('empty')) return t('Bitte gib die Adresse deines Servers ein.');
      if (m.includes('web address') || m.includes('host name'))
        return t('Das ist keine gültige Server-Adresse.');
      if (/incorrect|wrong|invalid/i.test(m) || m === 'Email or master password is wrong.')
        return t('E-Mail-Adresse oder Master-Passwort stimmt nicht.');
      return t('Der Server hat die Anmeldung abgelehnt: {reason}', { reason: m });
    case 'wrong-password':
      return t('Das Master-Passwort ist falsch.');
    case 'session-expired':
      return t('Die Sitzung ist abgelaufen. Bitte melde dich neu an.');
    case 'conflict':
      return t(
        'Dieser Eintrag wurde woanders geändert. UwULock hat nichts überschrieben – synchronisiere und bearbeite ihn noch einmal.',
      );
    case 'reprompt':
      return t('Dieser Eintrag fragt zuerst nach deinem Master-Passwort.');
    case 'server':
      return t('Der Server hat mit einem Fehler geantwortet: {reason}', { reason: m });
    case 'unsupported':
      return t('Das kann diese Beta noch nicht: {reason}', {
        reason: m.replace(/^not supported yet: /, ''),
      });
    case 'weaker-kdf':
      return t(
        'Der Server verlangt für dieses Konto eine schwächere Schlüsselableitung als bei der letzten Anmeldung, deshalb hat UwULock nichts gesendet. Wenn du sie selbst gesenkt hast, melde das Konto auf diesem Gerät ab und füge es neu hinzu.',
      );
    case 'crypto':
      return t('Etwas ließ sich nicht entschlüsseln: {reason}', { reason: m });
    case 'clipboard':
      return t('Kopieren hat nicht geklappt: {reason}', { reason: m });
    case 'locked':
      return t('Der Tresor ist gesperrt.');
    case 'not-found':
      return t('Das gibt es in diesem Eintrag nicht (mehr).');
    case 'invalid':
      if (m.startsWith("That doesn't look like an email"))
        return t('Das sieht nicht nach einer E-Mail-Adresse aus.');
      return m;
    default:
      return m;
  }
}
