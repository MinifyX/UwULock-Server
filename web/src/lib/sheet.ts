/**
 * The emergency sheet: a page to print and keep somewhere safe, for the people who need the
 * vault when its owner cannot open it. It is made here, in the browser; the server never gets
 * it. It carries the server's address and the account's address (as text and QR codes), a box
 * for the master password to be written in by hand, the recovery code of two-step login, and
 * what relatives should do — with the emergency contacts and their waiting times.
 */

import { encode } from 'uqr';
import { PAGE, Pdf } from './pdf';

export type SheetLanguage = 'de' | 'en';

export type SheetContact = {
  name: string | null;
  email: string | null;
  /** 0: may view the vault, 1: may take it over. */
  type: 0 | 1;
  waitTimeDays: number;
};

export type SheetInput = {
  server: string;
  email: string;
  /** Null: no two-step login is set up. */
  recoveryCode: string | null;
  contacts: SheetContact[];
  language: SheetLanguage;
  /** When it was made. */
  date: Date;
};

const TEXTS = {
  de: {
    title: 'Notfallblatt',
    lead: 'Mit diesem Blatt kommen deine Angehörigen an den Passwort-Tresor von {email}. Bewahr es sicher auf, zum Beispiel im Tresor, beim Testament oder beim Notar – wer es hat, kommt an alles.',
    server: 'Adresse des Servers',
    account: 'E-Mail-Adresse des Kontos',
    password: 'Master-Passwort',
    passwordHint: 'Von Hand eintragen, nicht am Computer. Groß- und Kleinschreibung zählen.',
    recovery: 'Wiederherstellungscode der Zwei-Schritt-Anmeldung',
    recoveryHint:
      'Schaltet die Zwei-Schritt-Anmeldung aus, wenn das Handy oder der Schlüssel fehlt. Danach gilt er nicht mehr.',
    noRecovery: 'Für dieses Konto ist keine Zwei-Schritt-Anmeldung eingerichtet.',
    steps: 'Was zu tun ist',
    step1: 'Die Adresse des Servers im Browser öffnen (oder den QR-Code scannen).',
    step2: 'Mit der E-Mail-Adresse und dem Master-Passwort anmelden.',
    step3:
      'Fragt der Server nach einem zweiten Schritt: „Wiederherstellungscode verwenden“ wählen und den Code von oben eingeben.',
    step4:
      'Im Tresor stehen alle Passwörter. Unter Einstellungen lässt er sich exportieren oder ausdrucken.',
    contacts: 'Notfallkontakte',
    contactsLead:
      'Diese Personen können im Web-Tresor unter Einstellungen › Notfallzugriff Zugriff anfragen – auch ohne dieses Blatt. Sagt niemand innerhalb der Wartezeit nein, bekommen sie ihn.',
    view: 'darf den Tresor ansehen',
    takeover: 'darf das Konto übernehmen',
    days: 'Wartezeit {n} Tage',
    day: 'Wartezeit 1 Tag',
    noContacts:
      'Es sind keine Notfallkontakte eingerichtet. Ohne das Master-Passwort kommt niemand an den Tresor – auch der Betreiber des Servers nicht.',
    footer: 'Erstellt am {date} in deinem Browser. Der Server hat dieses Blatt nie gesehen.',
  },
  en: {
    title: 'Emergency sheet',
    lead: "With this sheet your family can get into the password vault of {email}. Keep it somewhere safe, like a safe, with the will or at a notary's – whoever has it has everything.",
    server: 'Address of the server',
    account: 'Email address of the account',
    password: 'Master password',
    passwordHint: 'Write it in by hand, not on a computer. Upper and lower case matter.',
    recovery: 'Recovery code of two-step login',
    recoveryHint:
      'Turns two-step login off when the phone or the key is missing. It no longer works after that.',
    noRecovery: 'This account has no two-step login set up.',
    steps: 'What to do',
    step1: "Open the server's address in a browser (or scan the QR code).",
    step2: 'Log in with the email address and the master password.',
    step3:
      'If the server asks for a second step: choose “Use recovery code” and enter the code above.',
    step4: 'The vault holds every password. Under Settings it can be exported or printed.',
    contacts: 'Emergency contacts',
    contactsLead:
      'These people can ask for access in the web vault under Settings › Emergency access – even without this sheet. If nobody says no within the waiting time, they get it.',
    view: 'may view the vault',
    takeover: 'may take over the account',
    days: 'waiting time {n} days',
    day: 'waiting time 1 day',
    noContacts:
      "No emergency contacts are set up. Without the master password nobody gets into the vault – not even the server's operator.",
    footer: 'Made on {date} in your browser. The server never saw this sheet.',
  },
} as const;

const fill = (text: string, values: Record<string, string | number>) =>
  text.replace(/\{(\w+)\}/g, (_, key: string) => String(values[key] ?? ''));

/** The recovery code in groups of four, easier to copy by hand. */
function grouped(code: string): string {
  const clean = code.replace(/\s+/g, '').toUpperCase();
  return clean.match(/.{1,4}/g)?.join(' ') ?? clean;
}

/** The sheet as a PDF. */
export function emergencySheet(input: SheetInput): Uint8Array {
  const text = TEXTS[input.language];
  const pdf = new Pdf();
  const page = pdf.page();
  const left = 56;
  const right = PAGE.width - 56;
  const full = right - left;
  let top = 50;

  page.rect(left, top, 6, 26, true, 0);
  page.text(left + 16, top + 2, `UwULock – ${text.title}`, 20, 'bold');
  top += 42;
  top = page.paragraph(
    left,
    top,
    fill(text.lead, { email: input.email }),
    full,
    10.5,
    'regular',
    0.25,
  );
  top += 12;

  // The server and the account, each as text and as a QR code.
  const qrSize = 92;
  const column = (full - 24) / 2;
  const block = (x: number, label: string, value: string) => {
    page.text(x, top, label, 9, 'bold', 0.4);
    page.qr(x, top + 16, qrSize, encode(value).data);
    return page.paragraph(x, top + 16 + qrSize + 8, value, column, 11, 'bold');
  };
  top = Math.max(
    block(left, text.server, input.server),
    block(left + column + 24, text.account, input.email),
  );
  top += 14;

  // The master password: a box, with lines to write on.
  page.text(left, top, text.password, 9, 'bold', 0.4);
  top += 16;
  page.rect(left, top, full, 58, false, 0.35);
  page.line(left + 12, top + 26, right - 12, top + 26);
  page.line(left + 12, top + 48, right - 12, top + 48);
  top += 64;
  page.text(left, top, text.passwordHint, 8.5, 'regular', 0.4);
  top += 26;

  page.text(left, top, text.recovery, 9, 'bold', 0.4);
  top += 16;
  if (input.recoveryCode) {
    page.text(left, top, grouped(input.recoveryCode), 16, 'mono');
    top += 24;
    top = page.paragraph(left, top, text.recoveryHint, full, 8.5, 'regular', 0.4);
  } else {
    top = page.paragraph(left, top, text.noRecovery, full, 10.5);
  }
  top += 16;

  page.text(left, top, text.steps, 13, 'bold');
  top += 20;
  [text.step1, text.step2, text.step3, text.step4].forEach((step, index) => {
    page.text(left, top, `${index + 1}.`, 10.5, 'bold');
    top = page.paragraph(left + 16, top, step, full - 16, 10.5);
    top += 3;
  });
  top += 12;

  page.text(left, top, text.contacts, 13, 'bold');
  top += 20;
  if (input.contacts.length) {
    top = page.paragraph(left, top, text.contactsLead, full, 9.5, 'regular', 0.3);
    top += 4;
    for (const contact of input.contacts) {
      const who = [contact.name, contact.email ? `<${contact.email}>` : null]
        .filter(Boolean)
        .join(' ');
      const wait =
        contact.waitTimeDays === 1 ? text.day : fill(text.days, { n: contact.waitTimeDays });
      const may = contact.type === 1 ? text.takeover : text.view;
      top = page.paragraph(left + 10, top, `•  ${who} – ${may}, ${wait}`, full - 10, 10.5);
    }
  } else {
    top = page.paragraph(left, top, text.noContacts, full, 10.5);
  }

  const date = input.date.toLocaleDateString(input.language === 'de' ? 'de-DE' : 'en-GB', {
    dateStyle: 'long',
  });
  page.line(left, PAGE.height - 60, right, PAGE.height - 60, 0.8);
  page.text(left, PAGE.height - 52, fill(text.footer, { date }), 8, 'regular', 0.45);
  return pdf.bytes(`UwULock – ${text.title}`);
}
