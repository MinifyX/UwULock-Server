/**
 * What the web vault does beyond items: their attachments, Sends, emergency access, devices that
 * ask to log in, passkeys, the API key and the password check. The crypto for all of it runs
 * in the WebAssembly module; the server gets files and texts only encrypted.
 */

import { currentProfile, sync } from './api';
import { call, callJson } from './web/core';
import { deviceId, fetchBytes, request, upload } from './web/http';
import * as webauthn from './web/webauthn';

const id = encodeURIComponent;

async function hash(password: string): Promise<string> {
  return call((core) => core.passwordHash(password));
}

// ── Attachments ───────────────────────────────────────────

export type Attachment = { id: string; fileName: string; size: number };

export const attachmentsOf = (itemId: string) =>
  callJson<Attachment[]>((core) => core.attachments(itemId));

export async function addAttachment(itemId: string, file: File): Promise<void> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const sealed = await call((core) => core.sealAttachment(itemId, file.name, bytes));
  const meta = JSON.parse(sealed.meta) as { fileName: string; key: string; fileSize: number };
  const data = sealed.takeData();
  sealed.free();
  const answer = await request<{ url: string }>(`/api/ciphers/${id(itemId)}/attachment/v2`, {
    body: meta,
  });
  await upload(`/api${answer.url}`, data, meta.fileName);
  await sync();
}

export async function downloadAttachment(itemId: string, attachmentId: string): Promise<Blob> {
  const info = await request<{ url: string }>(
    `/api/ciphers/${id(itemId)}/attachment/${id(attachmentId)}`,
  );
  const bytes = await fetchBytes(info.url);
  const plain = await call((core) => core.openAttachment(itemId, attachmentId, bytes));
  return new Blob([plain as BlobPart]);
}

export async function deleteAttachment(itemId: string, attachmentId: string): Promise<void> {
  await request(`/api/ciphers/${id(itemId)}/attachment/${id(attachmentId)}`, { method: 'DELETE' });
  await sync();
}

// ── Sends ─────────────────────────────────────────────────

export type SendKind = 0 | 1;

export type Send = {
  id: string;
  accessId: string;
  kind: SendKind;
  name: string;
  notes: string | null;
  text: string | null;
  hidden: boolean;
  fileName: string | null;
  size: number | null;
  maxAccessCount: number | null;
  accessCount: number;
  hasPassword: boolean;
  disabled: boolean;
  hideEmail: boolean;
  revisionDate: string | null;
  expirationDate: string | null;
  deletionDate: string | null;
  urlKey: string;
};

export type SendDraft = {
  kind: SendKind;
  name: string;
  notes: string | null;
  text: string | null;
  hidden: boolean;
  fileName: string | null;
  /** A new password; `null` keeps the one there is. */
  password: string | null;
  maxAccessCount: number | null;
  expirationDate: string | null;
  deletionDate: string;
  disabled: boolean;
  hideEmail: boolean;
};

export const sendsList = () => callJson<Send[]>((core) => core.sends());

export const sendLink = (send: Pick<Send, 'accessId' | 'urlKey'>) =>
  `${location.origin}/#/send/${send.accessId}/${send.urlKey}`;

/** Save a Send; a new file Send uploads its file too. The link of a new one comes back. */
export async function saveSend(
  sendId: string | null,
  draft: SendDraft,
  file?: File,
): Promise<void> {
  const bytes = file ? new Uint8Array(await file.arrayBuffer()) : undefined;
  const sealed = await call((core) =>
    core.sealSend(
      sendId ?? '',
      JSON.stringify({ ...draft, fileName: file?.name ?? draft.fileName }),
      bytes,
    ),
  );
  const body = JSON.parse(sealed.meta) as Record<string, unknown>;
  const data = sealed.takeData();
  sealed.free();
  if (sendId) {
    await request(`/api/sends/${id(sendId)}`, { method: 'PUT', body });
  } else if (draft.kind === 1) {
    const answer = await request<{ url: string }>('/api/sends/file/v2', { body });
    const name = (body.file as { fileName: string }).fileName;
    await upload(`/api${answer.url}`, data, name);
  } else {
    await request('/api/sends', { body });
  }
  await sync();
}

export async function deleteSend(sendId: string): Promise<void> {
  await request(`/api/sends/${id(sendId)}`, { method: 'DELETE' });
  await sync();
}

export async function removeSendPassword(sendId: string): Promise<void> {
  await request(`/api/sends/${id(sendId)}/remove-password`, { method: 'PUT' });
  await sync();
}

export type OpenedSend = {
  id: string;
  kind: SendKind;
  name: string | null;
  text: string | null;
  hidden: boolean;
  fileId: string | null;
  fileName: string | null;
  size: string | null;
  expirationDate: string | null;
  creator: string | null;
  /** The password's hash, for the file. */
  password: string | null;
};

/** A Send, for whoever has its link. Throws `{ kind: 'password' }` when it wants one. */
export async function openSend(
  accessId: string,
  urlKey: string,
  password?: string,
): Promise<OpenedSend> {
  const passwordHash = password
    ? await call((core) => core.sendAccessPassword(password, urlKey))
    : null;
  let access: Record<string, unknown>;
  try {
    access = await request<Record<string, unknown>>(`/api/sends/access/${id(accessId)}`, {
      body: passwordHash ? { password: passwordHash } : {},
      auth: false,
    });
  } catch (error) {
    const status = (error as { status?: number }).status;
    if (status === 401) throw { kind: 'password', message: 'This Send has a password.' };
    throw error;
  }
  const opened = await callJson<Omit<OpenedSend, 'id' | 'password'>>((core) =>
    core.openSendAccess(JSON.stringify(access), urlKey),
  );
  return { ...opened, id: String(access.id), password: passwordHash };
}

export async function downloadSendFile(send: OpenedSend, urlKey: string): Promise<Blob> {
  const answer = await request<{ url: string }>(
    `/api/sends/${id(send.id)}/access/file/${id(send.fileId ?? '')}`,
    { body: send.password ? { password: send.password } : {}, auth: false },
  );
  const bytes = await fetchBytes(answer.url);
  const plain = await call((core) => core.openSendFile(urlKey, bytes));
  return new Blob([plain as BlobPart]);
}

// ── Emergency access ──────────────────────────────────────

export const EMERGENCY_STATUS = {
  invited: 0,
  accepted: 1,
  confirmed: 2,
  asked: 3,
  approved: 4,
} as const;

export type Contact = {
  id: string;
  granteeId?: string | null;
  grantorId?: string;
  name: string | null;
  email: string | null;
  type: 0 | 1;
  status: number;
  waitTimeDays: number;
  creationDate: string;
};

type List<T> = { data: T[] };

export const trustedContacts = async () =>
  (await request<List<Contact>>('/api/emergency-access/trusted')).data;
export const grantedAccess = async () =>
  (await request<List<Contact>>('/api/emergency-access/granted')).data;

export const inviteContact = (email: string, type: 0 | 1, waitTimeDays: number) =>
  request('/api/emergency-access/invite', { body: { email, type, waitTimeDays } });

export const reinviteContact = (accessId: string) =>
  request(`/api/emergency-access/${id(accessId)}/reinvite`, { method: 'POST' });

export const updateContact = (contact: Contact, type: 0 | 1, waitTimeDays: number) =>
  request(`/api/emergency-access/${id(contact.id)}`, {
    method: 'PUT',
    body: { type, waitTimeDays },
  });

export const removeContact = (accessId: string) =>
  request(`/api/emergency-access/${id(accessId)}`, { method: 'DELETE' });

export const acceptContact = (accessId: string, token: string) =>
  request(`/api/emergency-access/${id(accessId)}/accept`, { body: { token } });

/** The contact's public key and its fingerprint phrase, to compare before confirming. */
export async function contactKey(contact: Contact): Promise<{ publicKey: string; phrase: string }> {
  const answer = await request<{ publicKey: string }>(
    `/api/users/${id(contact.granteeId ?? '')}/public-key`,
  );
  const phrase = await call((core) => core.fingerprint(contact.granteeId ?? '', answer.publicKey));
  return { publicKey: answer.publicKey, phrase };
}

export async function confirmContact(contact: Contact, publicKey: string): Promise<void> {
  const key = await call((core) => core.wrapUserKey(publicKey));
  await request(`/api/emergency-access/${id(contact.id)}/confirm`, { body: { key } });
}

export const answerRecovery = (accessId: string, approve: boolean) =>
  request(`/api/emergency-access/${id(accessId)}/${approve ? 'approve' : 'reject'}`, {
    method: 'POST',
  });

export const askForAccess = (accessId: string) =>
  request(`/api/emergency-access/${id(accessId)}/initiate`, { method: 'POST' });

/** The grantor's vault, as Bitwarden's JSON export: to look at, and to save. */
export async function emergencyVault(accessId: string): Promise<string> {
  const view = await request<{ keyEncrypted: string; ciphers: unknown[] }>(
    `/api/emergency-access/${id(accessId)}/view`,
    { method: 'POST' },
  );
  return call((core) => core.emergencyView(view.keyEncrypted, JSON.stringify(view.ciphers)));
}

export async function takeOver(access: Contact, password: string): Promise<void> {
  const answer = await request<Record<string, unknown>>(
    `/api/emergency-access/${id(access.id)}/takeover`,
    { method: 'POST' },
  );
  const kdf = JSON.stringify({
    kdf: answer.kdf,
    kdfIterations: answer.kdfIterations,
    kdfMemory: answer.kdfMemory,
    kdfParallelism: answer.kdfParallelism,
  });
  const body = await callJson<unknown>((core) =>
    core.emergencyTakeover(String(answer.keyEncrypted), access.email ?? '', kdf, password),
  );
  await request(`/api/emergency-access/${id(access.id)}/password`, { body });
}

// ── Devices that ask to log in ────────────────────────────

export type DeviceRequest = {
  id: string;
  publicKey: string;
  requestDeviceType: string;
  requestIpAddress: string;
  creationDate: string;
};

export const pendingRequests = async () =>
  (await request<List<DeviceRequest>>('/api/auth-requests/pending')).data;

/** The phrase the other device shows: the account's address and the request's key. */
export async function requestPhrase(email: string, publicKey: string): Promise<string> {
  return call((core) => core.fingerprint(email.trim().toLowerCase(), publicKey));
}

export async function answerRequest(requestId: string, publicKey: string, approve: boolean) {
  const key = approve ? await call((core) => core.wrapUserKey(publicKey)) : null;
  await request(`/api/auth-requests/${id(requestId)}`, {
    method: 'PUT',
    body: { deviceIdentifier: deviceId(), key, requestApproved: approve },
  });
}

// ── Passkeys ──────────────────────────────────────────────

export type Passkey = {
  id: string;
  name: string;
  /** 0 unlocks, 1 could, 2 cannot. */
  prfStatus: 0 | 1 | 2;
  encryptedPublicKey: string | null;
  creationDate: string;
};

export const passkeys = async () => (await request<List<Passkey>>('/api/webauthn')).data;

/** A new passkey that logs in — and, where it can, unlocks the vault too. */
export async function addPasskey(name: string, password: string): Promise<boolean> {
  const masterPasswordHash = await hash(password);
  const offer = await request<{ options: Record<string, unknown>; token: string }>(
    '/api/webauthn/attestation-options',
    { body: { masterPasswordHash } },
  );
  const salt = await call((core) => core.prfSalt());
  const credential = await webauthn.create(webauthn.creationOptions(offer.options, salt));
  const supportsPrf = webauthn.prfEnabled(credential);
  const prf = webauthn.prfOutput(credential);
  const keys = prf ? await callJson<Record<string, string>>((core) => core.prfKeySet(prf)) : {};
  await request('/api/webauthn', {
    body: {
      deviceResponse: webauthn.attestationJson(credential),
      name,
      token: offer.token,
      supportsPrf,
      ...keys,
    },
  });
  if (prf || !supportsPrf) return Boolean(prf);
  // The passkey can, but gave no output when it was made: once more, to get it.
  return enablePasskeyUnlock(password);
}

/** Turn on unlocking for the passkey the browser picks, with its PRF output. */
export async function enablePasskeyUnlock(password: string): Promise<boolean> {
  const masterPasswordHash = await hash(password);
  const offer = await request<{ options: Record<string, unknown>; token: string }>(
    '/api/webauthn/assertion-options',
    { body: { masterPasswordHash } },
  );
  const salt = await call((core) => core.prfSalt());
  const credential = await webauthn.get(webauthn.requestOptions(offer.options, salt));
  const prf = webauthn.prfOutput(credential);
  if (!prf) return false;
  const keys = await callJson<Record<string, string>>((core) => core.prfKeySet(prf));
  await request('/api/webauthn', {
    method: 'PUT',
    body: { deviceResponse: webauthn.assertionJson(credential), token: offer.token, ...keys },
  });
  return true;
}

export async function removePasskey(passkeyId: string, password: string): Promise<void> {
  const masterPasswordHash = await hash(password);
  await request(`/api/webauthn/${id(passkeyId)}/delete`, { body: { masterPasswordHash } });
}

// ── Security keys for the second step ─────────────────────

export type SecurityKey = { id: number; name: string };

export async function securityKeys(password: string): Promise<SecurityKey[]> {
  const masterPasswordHash = await hash(password);
  const answer = await request<{ keys: SecurityKey[] }>('/api/two-factor/get-webauthn', {
    body: { masterPasswordHash },
  });
  return answer.keys;
}

export async function addSecurityKey(name: string, password: string, slot: number): Promise<void> {
  const masterPasswordHash = await hash(password);
  const options = await request<Record<string, unknown>>('/api/two-factor/get-webauthn-challenge', {
    body: { masterPasswordHash },
  });
  const credential = await webauthn.create(webauthn.creationOptions(options));
  await request('/api/two-factor/webauthn', {
    method: 'PUT',
    body: {
      id: slot,
      name,
      deviceResponse: webauthn.attestationJson(credential),
      masterPasswordHash,
    },
  });
}

export async function removeSecurityKey(slot: number, password: string): Promise<void> {
  const masterPasswordHash = await hash(password);
  await request('/api/two-factor/webauthn', {
    method: 'DELETE',
    body: { id: slot, masterPasswordHash },
  });
}

// ── The API key ───────────────────────────────────────────

export async function apiKey(password: string, rotate = false) {
  const masterPasswordHash = await hash(password);
  const answer = await request<{ apiKey: string }>(
    rotate ? '/api/accounts/rotate-api-key' : '/api/accounts/api-key',
    { body: { masterPasswordHash } },
  );
  const userId = String(currentProfile()?.id ?? '');
  return { clientId: `user.${userId}`, clientSecret: answer.apiKey };
}

// ── The password check ────────────────────────────────────

export type Finding = {
  id: string;
  name: string;
  subtitle: string | null;
  bits: number;
  weak: boolean;
  reused: number;
  unsecured: boolean;
  /** Times it was in a breach; `null` when that was not checked. */
  breached: number | null;
};

export type Report = {
  findings: Finding[];
  checked: number;
  breachesChecked: boolean;
  /** Have I Been Pwned did not answer for some passwords. */
  breachesIncomplete: boolean;
};

/** Check every login's password; with `breaches`, also against Have I Been Pwned. */
export async function passwordReport(
  breaches: boolean,
  progress?: (done: number, total: number) => void,
): Promise<Report> {
  const report = await callJson<{
    findings: Omit<Finding, 'breached'>[];
    prefixes: string[];
    checked: number;
  }>((core) => core.passwordReport());
  const counts = new Map<string, number>();
  let incomplete = false;
  if (breaches) {
    const queue = [...report.prefixes];
    let done = 0;
    const worker = async () => {
      for (let prefix = queue.shift(); prefix; prefix = queue.shift()) {
        try {
          const range = await request<string>(`/uwu/v1/hibp/${prefix}`);
          const found = await callJson<[string, number][]>((core) =>
            core.breaches(prefix, String(range)),
          );
          for (const [item, count] of found) counts.set(item, count);
        } catch {
          // The rest of the report still counts.
          incomplete = true;
        }
        progress?.(++done, report.prefixes.length);
      }
    };
    await Promise.all([worker(), worker(), worker(), worker()]);
  }
  return {
    findings: report.findings.map((finding) => ({
      ...finding,
      breached: breaches ? (counts.get(finding.id) ?? 0) : null,
    })),
    checked: report.checked,
    breachesChecked: breaches,
    breachesIncomplete: incomplete,
  };
}
