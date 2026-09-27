/**
 * The WebAuthn connector: what Bitwarden's browser extension, desktop app and phone apps open on
 * the web vault's address when an account's second step is a security key. They cannot ask for
 * a key under this server's name themselves, so this page does it for them and hands the answer
 * back — to the frame's parent by `postMessage`, or to the app by its callback link.
 *
 * The same protocol as Bitwarden's web vault (`webauthn-connector.html`,
 * `webauthn-mobile-connector.html`), so the official clients work unchanged:
 *
 * - `data`: base64 of JSON — in version 2 `{ data, headerText, btnText, btnReturnText, mobile? }`,
 *   where `data` is the server's options as JSON text; in version 1 the options themselves.
 * - `parent`: the page that framed this one; answers go there as `info|ready`, `success|<json>`
 *   or `error|<message>`, and it may send `stop` and `start`.
 * - For the phone apps: the answer goes to `bitwarden://webauthn-callback?data=…` (or `?error=…`).
 */

import './connector.css';
import { answerJson, param, readData, requestOptions } from './common';

let options: PublicKeyCredentialRequestOptions | null = null;
let parentUrl: string | null = null;
let callbackUri: string | null = null;
let buttonText = '';
let returnText = '';
let stopped = false;
let answered = false;

const button = () => document.getElementById('webauthn-button') as HTMLButtonElement | null;

function post(message: string) {
  if (parentUrl) parent.postMessage(message, parentUrl);
}

function goBack(uri: string) {
  document.location.replace(uri);
  // In case the browser does not follow a scripted navigation to an app.
  const back = button();
  if (back) {
    back.textContent = returnText || 'Return';
    back.onclick = () => document.location.replace(uri);
  }
}

function error(message: string) {
  if (callbackUri) goBack(`${callbackUri}?error=${encodeURIComponent(message)}`);
  else post(`error|${message}`);
  reset();
}

function reset() {
  const start = button();
  if (!start) return;
  start.textContent = buttonText || 'Use security key';
  start.disabled = false;
  start.onclick = () => void run();
}

async function run() {
  if (!options || answered) return;
  if (stopped) {
    reset();
    return;
  }
  const start = button();
  if (start) start.disabled = true;
  try {
    const credential = (await navigator.credentials.get({
      publicKey: options,
    })) as PublicKeyCredential;
    if (answered) return;
    const answer = JSON.stringify(answerJson(credential));
    answered = true;
    if (callbackUri) goBack(`${callbackUri}?data=${encodeURIComponent(answer)}`);
    else post(`success|${answer}`);
  } catch (e) {
    error(e instanceof Error ? e.message : String(e));
  }
}

function init() {
  const parentParam = param('parent');
  parentUrl = parentParam ? decodeURIComponent(parentParam) : null;
  const data = readData(param('v'));
  if (!data) {
    error('No data.');
    return;
  }
  buttonText = data.btnText ?? '';
  returnText = data.btnReturnText ?? '';
  const header = document.getElementById('webauthn-header');
  if (header && data.headerText) header.textContent = data.headerText;
  const scheme = (param('deeplinkScheme') ?? '').toLowerCase();
  if (scheme === 'https') callbackUri = 'https://bitwarden.com/webauthn-callback';
  else if (scheme || data.mobile === true || data.callbackUri != null)
    callbackUri = 'bitwarden://webauthn-callback';
  if (!parentUrl && !callbackUri) {
    error('No return target provided.');
    return;
  }
  if (!('credentials' in navigator)) {
    error('WebAuthn is not supported in this browser.');
    return;
  }
  try {
    options = requestOptions(data.data);
  } catch {
    error('Cannot parse webauthn data.');
    return;
  }
  reset();
  window.addEventListener('message', (event) => {
    if (parentUrl && event.origin !== new URL(parentUrl).origin) return;
    if (event.data === 'stop') {
      stopped = true;
      reset();
    } else if (event.data === 'start' && stopped) {
      stopped = false;
      void run();
    }
  });
  post('info|ready');
  // Safari and the phones only let a page ask for a key after a tap.
  const safari = / Safari\//.test(navigator.userAgent) && !/Chrome/.test(navigator.userAgent);
  if (!callbackUri && !safari) void run();
}

document.addEventListener('DOMContentLoaded', init);
