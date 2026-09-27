/** What the WebAuthn connectors share: reading the query, and WebAuthn's bytes in base64url. */

export function param(name: string): string | null {
  return new URLSearchParams(location.search).get(name);
}

/** base64 of UTF-8, the way Bitwarden's clients encode `data`. */
export function b64Decode(text: string): string {
  const bytes = Uint8Array.from(atob(text.replace(/ /g, '+')), (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

export type ConnectorData = {
  data: string;
  headerText?: string;
  btnText?: string;
  btnReturnText?: string;
  callbackUri?: string;
  mobile?: boolean;
};

/** `data` from the query: version 1 is the options alone, version 2 wraps them. */
export function readData(version: string | null): ConnectorData | null {
  const raw = param('data');
  if (!raw) return null;
  try {
    const text = b64Decode(raw);
    if (version === '1') {
      return {
        data: text,
        headerText: param('headerText') ?? undefined,
        btnText: param('btnText') ?? undefined,
        btnReturnText: param('btnReturnText') ?? undefined,
      };
    }
    return JSON.parse(text) as ConnectorData;
  } catch {
    return null;
  }
}

function fromBase64Url(text: string): Uint8Array<ArrayBuffer> {
  const plain = text.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(plain + '='.repeat((4 - (plain.length % 4)) % 4)), (c) =>
    c.charCodeAt(0),
  );
}

function toBase64Url(bytes: ArrayBuffer): string {
  let text = '';
  for (const byte of new Uint8Array(bytes)) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** The server's options, from JSON text, for `navigator.credentials.get()`. */
export function requestOptions(json: string): PublicKeyCredentialRequestOptions {
  const value = JSON.parse(json) as Record<string, unknown>;
  return {
    challenge: fromBase64Url(String(value.challenge)),
    timeout: Number(value.timeout ?? 300_000),
    rpId: value.rpId as string | undefined,
    allowCredentials: ((value.allowCredentials as { id: string }[] | undefined) ?? []).map(
      (entry) => ({ type: 'public-key' as const, id: fromBase64Url(entry.id) }),
    ),
    userVerification: (value.userVerification as UserVerificationRequirement) ?? 'discouraged',
  };
}

/** The answer, as Bitwarden's clients pass it to the server. */
export function answerJson(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    extensions: credential.getClientExtensionResults(),
    response: {
      authenticatorData: toBase64Url(response.authenticatorData),
      clientDataJson: toBase64Url(response.clientDataJSON),
      signature: toBase64Url(response.signature),
    },
  };
}
