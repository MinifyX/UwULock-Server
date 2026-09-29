/**
 * The way back from an SSO login (docs/uwu-api.md §19.2 step 4), at the path Bitwarden's clients
 * use: the server sends the browser here with `code` and `state` (or `error`), and this page
 * hands them on — to Bitwarden's browser extension (which listens for `authResult`), to the
 * desktop app, or to the web vault or admin portal that started the login.
 */

import './connector.css';
import { param } from './common';

const german = (navigator.languages?.[0] ?? navigator.language ?? '')
  .toLowerCase()
  .startsWith('de');
const say = (de: string, en: string) => (german ? de : en);

function show(title: string, message: string) {
  document.getElementById('title')!.textContent = title;
  document.getElementById('msg')!.textContent = message;
}

const code = param('code');
const state = param('state') ?? '';
const error = param('error');

if (state.includes(':clientId=browser')) {
  // Bitwarden's extension: its content script on this page takes the result.
  window.postMessage(
    { command: 'authResult', code, state, lastpass: false },
    window.location.origin,
  );
  show(
    say('Angemeldet ✧', 'Logged in ✧'),
    say(
      'Die Erweiterung übernimmt jetzt. Du kannst diesen Tab schließen.',
      'The extension takes over now. You can close this tab.',
    ),
  );
} else if (state.includes(':clientId=desktop')) {
  const query = new URLSearchParams(
    code ? { code, state } : { error: error ?? 'access_denied', state },
  );
  location.replace(`bitwarden://sso-callback?${query}`);
  show(say('Zurück zur App …', 'Back to the app …'), '');
} else {
  const target = state.includes(':admin') ? '/admin' : '/';
  const query = new URLSearchParams(
    code
      ? { code, state }
      : {
          error: error ?? 'access_denied',
          error_description: param('error_description') ?? '',
          state,
        },
  );
  location.replace(`${target}#/sso?${query}`);
  show(say('Weiter …', 'Going on …'), '');
}
