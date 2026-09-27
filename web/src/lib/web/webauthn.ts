/**
 * WebAuthn in the browser: the server's options (JSON, with base64url bytes) turned into what
 * `navigator.credentials` takes, and its answers turned back into JSON the way Bitwarden's
 * clients send them.
 */

export function toBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const array = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let text = '';
  for (const byte of array) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function toBase64(bytes: ArrayBuffer | Uint8Array): string {
  const array = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let text = '';
  for (const byte of array) text += String.fromCharCode(byte);
  return btoa(text);
}

export function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  const plain = text.replace(/-/g, '+').replace(/_/g, '/');
  const padded = plain + '='.repeat((4 - (plain.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

type Json = Record<string, unknown>;

/** Whether this browser can do WebAuthn at all. */
export function available(): boolean {
  return typeof window.PublicKeyCredential === 'function' && 'credentials' in navigator;
}

/** Options for `create()`, from the server's JSON. */
export function creationOptions(json: Json, prfSalt?: string): PublicKeyCredentialCreationOptions {
  const user = json.user as Json;
  const options: PublicKeyCredentialCreationOptions = {
    rp: json.rp as PublicKeyCredentialRpEntity,
    user: {
      id: fromBase64(String(user.id)),
      name: String(user.name),
      displayName: String(user.displayName ?? user.name),
    },
    challenge: fromBase64(String(json.challenge)),
    pubKeyCredParams: json.pubKeyCredParams as PublicKeyCredentialParameters[],
    timeout: Number(json.timeout ?? 300_000),
    attestation: 'none',
    authenticatorSelection: json.authenticatorSelection as AuthenticatorSelectionCriteria,
    excludeCredentials: ((json.excludeCredentials as Json[] | undefined) ?? []).map((entry) => ({
      type: 'public-key',
      id: fromBase64(String(entry.id)),
    })),
  };
  if (prfSalt) {
    options.extensions = {
      prf: { eval: { first: fromBase64(prfSalt) } },
    } as AuthenticationExtensionsClientInputs;
  }
  return options;
}

/** Options for `get()`, from the server's JSON. */
export function requestOptions(json: Json, prfSalt?: string): PublicKeyCredentialRequestOptions {
  const options: PublicKeyCredentialRequestOptions = {
    challenge: fromBase64(String(json.challenge)),
    timeout: Number(json.timeout ?? 300_000),
    rpId: json.rpId as string | undefined,
    allowCredentials: ((json.allowCredentials as Json[] | undefined) ?? []).map((entry) => ({
      type: 'public-key',
      id: fromBase64(String(entry.id)),
    })),
    userVerification: (json.userVerification as UserVerificationRequirement) ?? 'preferred',
  };
  if (prfSalt) {
    options.extensions = {
      prf: { eval: { first: fromBase64(prfSalt) } },
    } as AuthenticationExtensionsClientInputs;
  }
  return options;
}

/** A new credential, as the server takes it. */
export function attestationJson(credential: PublicKeyCredential): Json {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    extensions: {},
    response: {
      attestationObject: toBase64Url(response.attestationObject),
      clientDataJson: toBase64Url(response.clientDataJSON),
    },
  };
}

/** An assertion, as the server takes it. */
export function assertionJson(credential: PublicKeyCredential): Json {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    extensions: {},
    response: {
      authenticatorData: toBase64Url(response.authenticatorData),
      clientDataJson: toBase64Url(response.clientDataJSON),
      signature: toBase64Url(response.signature),
      userHandle: response.userHandle ? toBase64Url(response.userHandle) : null,
    },
  };
}

/** The PRF output of a passkey's answer, base64, if it gave one. */
export function prfOutput(credential: PublicKeyCredential): string | null {
  const results = credential.getClientExtensionResults() as {
    prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } };
  };
  const first = results.prf?.results?.first;
  return first ? toBase64(first) : null;
}

/** Whether a new passkey said it can do PRF. */
export function prfEnabled(credential: PublicKeyCredential): boolean {
  const results = credential.getClientExtensionResults() as {
    prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } };
  };
  return Boolean(results.prf?.enabled || results.prf?.results?.first);
}

export async function create(options: PublicKeyCredentialCreationOptions) {
  const credential = await navigator.credentials.create({ publicKey: options });
  if (!credential) throw { kind: 'cancelled', message: 'Cancelled.' };
  return credential as PublicKeyCredential;
}

export async function get(options: PublicKeyCredentialRequestOptions) {
  const credential = await navigator.credentials.get({ publicKey: options });
  if (!credential) throw { kind: 'cancelled', message: 'Cancelled.' };
  return credential as PublicKeyCredential;
}
