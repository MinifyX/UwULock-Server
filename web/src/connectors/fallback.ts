/**
 * The WebAuthn fallback: where Bitwarden's browser extension sends the second step when it
 * cannot frame the connector (Firefox, Safari). A page of its own, with a button; the answer is
 * posted to this window, where the extension's content script picks it up.
 */

import './connector.css';
import { answerJson, param, readData, requestOptions } from './common';

const german = (param('locale') ?? navigator.language).toLowerCase().startsWith('de');
const text = german
  ? {
      title: 'Bestätige, dass du es bist',
      lead: 'Nimm deinen Sicherheitsschlüssel, um die Anmeldung abzuschließen.',
      button: 'Sicherheitsschlüssel verwenden',
      remember: '30 Tage lang auf diesem Gerät nicht mehr fragen',
      done: 'Fertig. Du kannst diesen Tab schließen.',
      unsupported: 'Dieser Browser kann keine Sicherheitsschlüssel.',
    }
  : {
      title: 'Verify it’s you',
      lead: 'Use your security key to finish logging in.',
      button: 'Use security key',
      remember: 'Don’t ask again on this device for 30 days',
      done: 'Done. You can close this tab.',
      unsupported: 'This browser cannot use security keys.',
    };

let sent = false;

function show(message: string, tone: 'info' | 'error') {
  const box = document.getElementById('msg');
  if (!box) return;
  box.textContent = message;
  box.dataset.tone = tone;
  box.hidden = false;
}

async function run() {
  if (sent) return;
  if (!('credentials' in navigator)) {
    show(text.unsupported, 'error');
    return;
  }
  const data = readData(param('v'));
  if (!data) {
    show('No data.', 'error');
    return;
  }
  try {
    const credential = (await navigator.credentials.get({
      publicKey: requestOptions(data.data),
    })) as PublicKeyCredential;
    if (sent) return;
    const remember = (document.getElementById('remember') as HTMLInputElement).checked;
    window.postMessage(
      { command: 'webAuthnResult', data: JSON.stringify(answerJson(credential)), remember },
      '*',
    );
    sent = true;
    (document.getElementById('webauthn-button') as HTMLButtonElement).disabled = true;
    show(text.done, 'info');
  } catch (e) {
    show(e instanceof Error ? e.message : String(e), 'error');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('title')!.textContent = text.title;
  document.getElementById('lead')!.textContent = text.lead;
  document.getElementById('remember-label')!.textContent = text.remember;
  const button = document.getElementById('webauthn-button') as HTMLButtonElement;
  button.textContent = text.button;
  button.onclick = () => void run();
});
