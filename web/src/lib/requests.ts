/**
 * File requests (docs/uwu-api.md §11): a link somebody without an account uploads files and a
 * message to, encrypted in their browser for this account's public key. The owner's label and
 * the link's secret are kept under the account's extras key (§3), so the link can be shown
 * again; the crypto for all of it runs in the WebAssembly module.
 */

import { saveItem, sync } from './api';
import { Upload } from '../wasm/pkg/core.js';
import { call, callJson, load } from './web/core';
import { ApiError, download, request } from './web/http';

const id = encodeURIComponent;

type List<T> = { data: T[] };

type Keys = { extrasKey: unknown; lost: boolean };
type Resolved =
  | { action: 'open'; rewrap: { userKeyWrapped: string } | null }
  | { action: 'create'; request: { userKeyWrapped: string; publicKeyWrapped: string } }
  | { action: 'lost' };

/**
 * Opens the account's extras key, making one the first time and wrapping it again for the user
 * key after an official client rotated it. Throws `{ kind: 'extras-lost' }` when the key pair
 * changed and nothing under the old key opens any more.
 */
export async function openExtras(): Promise<void> {
  for (let attempt = 0; attempt < 2; attempt++) {
    const keys = await request<Keys>('/uwu/v1/keys');
    const resolved = await callJson<Resolved>((core) => core.extrasKey(JSON.stringify(keys)));
    if (resolved.action === 'lost')
      throw { kind: 'extras-lost', message: 'The extras key of this account is lost.' };
    if (resolved.action === 'open') {
      // A failed wrap costs nothing but trying again next time.
      if (resolved.rewrap)
        await request('/uwu/v1/keys/user-wrap', { method: 'PUT', body: resolved.rewrap }).catch(
          () => undefined,
        );
      return;
    }
    try {
      await request('/uwu/v1/keys', { body: resolved.request });
      return;
    } catch (error) {
      // Another client was quicker: take its key.
      if ((error as ApiError).status !== 409) throw error;
    }
  }
}

/** Start over after the extras key was lost: it goes, and the labels of file requests with it. */
export async function resetExtras(password: string): Promise<void> {
  const masterPasswordHash = await call((core) => core.passwordHash(password));
  await request('/uwu/v1/keys', { method: 'DELETE', body: { masterPasswordHash } });
}

type Stored = {
  id: string;
  accessId: string;
  name: string | null;
  linkSecret: string | null;
  publicInfo: string;
  passwordSet: boolean;
  expirationDate: string;
  deletionDate: string;
  maxSubmissions: number | null;
  submissionCount: number;
  maxFiles: number;
  maxFileBytes: number;
  textAllowed: boolean;
  sendDomainId: string | null;
  disabled: boolean;
  unseen: number;
  bytes: number;
  creationDate: string;
  revisionDate: string;
};

export type FileRequest = Omit<Stored, 'name' | 'linkSecret' | 'publicInfo'> & {
  /** The owner's label; null when it no longer opens (the extras key was reset). */
  name: string | null;
  /** The link's secret, for showing the link again; null when it no longer opens. */
  secret: string | null;
  title: string | null;
  note: string | null;
  owner: string | null;
};

async function opened(stored: Stored): Promise<FileRequest> {
  const open = await callJson<{
    name: string | null;
    secret: string | null;
    title: string | null;
    note: string | null;
    owner: string | null;
  }>((core) => core.openFileRequest(JSON.stringify(stored)));
  const rest: Partial<Stored> = { ...stored };
  delete rest.linkSecret;
  delete rest.publicInfo;
  return { ...(rest as Stored), ...open };
}

export async function fileRequests(): Promise<FileRequest[]> {
  await openExtras();
  const list = await request<List<Stored>>('/uwu/v1/file-requests');
  return Promise.all(list.data.map(opened));
}

/** The link to hand out, on this server's address. */
export function requestLink(fileRequest: FileRequest): string | null {
  if (!fileRequest.secret) return null;
  return `${location.origin}/#/request/${fileRequest.accessId}/${fileRequest.secret}`;
}

export type RequestDraft = {
  name: string;
  title: string;
  note: string | null;
  owner: string | null;
  /** A new password; empty keeps the one there is (or none). */
  password: string | null;
  removePassword: boolean;
  expirationDate: string;
  maxSubmissions: number | null;
  maxFiles: number;
  maxFileBytes: number;
  textAllowed: boolean;
  disabled: boolean;
  /** A new link: the old one stops working. */
  newLink: boolean;
};

export async function saveFileRequest(
  existing: FileRequest | null,
  draft: RequestDraft,
): Promise<FileRequest> {
  await openExtras();
  const secret = existing && !draft.newLink ? existing.secret : null;
  // Without the old secret the page cannot keep the link: it makes a new one.
  const sealed = await callJson<{
    name: string;
    linkSecret: string;
    publicInfo: string;
    passwordHash: string | null;
    secret: string;
  }>((core) =>
    core.sealFileRequest(
      JSON.stringify({
        name: draft.name,
        title: draft.title,
        note: draft.note,
        owner: draft.owner,
        password: draft.password,
        secret,
      }),
    ),
  );
  // The password is hashed with the link's secret: a new link needs it again, or none.
  const keepsPassword = existing && !draft.newLink && secret && !draft.password;
  const body: Record<string, unknown> = {
    name: sealed.name,
    linkSecret: sealed.linkSecret,
    publicInfo: sealed.publicInfo,
    expirationDate: draft.expirationDate,
    maxSubmissions: draft.maxSubmissions,
    maxFiles: draft.maxFiles,
    maxFileBytes: draft.maxFileBytes,
    textAllowed: draft.textAllowed,
    disabled: draft.disabled,
    removePassword: draft.removePassword || (!keepsPassword && !sealed.passwordHash),
  };
  if (!keepsPassword) body.passwordHash = sealed.passwordHash;
  const stored = existing
    ? await request<Stored>(`/uwu/v1/file-requests/${id(existing.id)}`, { method: 'PUT', body })
    : await request<Stored>('/uwu/v1/file-requests', { body });
  return opened(stored);
}

export async function deleteFileRequest(requestId: string): Promise<void> {
  await request(`/uwu/v1/file-requests/${id(requestId)}`, { method: 'DELETE' });
}

type StoredSubmission = {
  id: string;
  requestId: string;
  creationDate: string;
  wrappedKey: string;
  sender: string | null;
  text: string | null;
  files: { id: string; fileName: string; key: string; size: number }[];
  seen: boolean;
};

export type Arrived = {
  id: string;
  requestId: string;
  creationDate: string;
  seen: boolean;
  text: string | null;
  /** As the uploader typed it; nobody checked it. */
  sender: { name?: string | null; email?: string | null } | null;
  files: { id: string; name: string; size: number }[];
  stored: StoredSubmission;
};

export async function submissions(requestId: string): Promise<Arrived[]> {
  const list = await request<List<StoredSubmission>>(
    `/uwu/v1/file-requests/${id(requestId)}/submissions`,
  );
  return Promise.all(
    list.data.map(async (stored) => {
      const open = await callJson<Pick<Arrived, 'text' | 'sender' | 'files'>>((core) =>
        core.openSubmission(JSON.stringify(stored)),
      );
      return {
        id: stored.id,
        requestId: stored.requestId,
        creationDate: stored.creationDate,
        seen: stored.seen,
        ...open,
        stored,
      };
    }),
  );
}

const submissionPath = (arrived: Arrived) =>
  `/uwu/v1/file-requests/${id(arrived.requestId)}/submissions/${id(arrived.id)}`;

export async function downloadArrivedFile(arrived: Arrived, fileId: string): Promise<Blob> {
  const blob = await download(`${submissionPath(arrived)}/files/${id(fileId)}`);
  const bytes = new Uint8Array(await blob.arrayBuffer());
  const plain = await call((core) =>
    core.openSubmissionFile(JSON.stringify(arrived.stored), fileId, bytes),
  );
  return new Blob([plain as BlobPart]);
}

export const markSeen = (arrived: Arrived) =>
  request(`${submissionPath(arrived)}/seen`, { body: {} });

export const deleteArrived = (arrived: Arrived) =>
  request(submissionPath(arrived), { method: 'DELETE' });

/**
 * Takes a submission over into a new secure note: the message and the sender in its notes, the
 * files as its attachments — moved on the server, not uploaded again. Then the submission goes.
 * Answers the new item's id.
 */
export async function takeOver(
  arrived: Arrived,
  name: string,
  senderLine: string,
): Promise<string> {
  const notes = [arrived.text ?? '', senderLine].filter(Boolean).join('\n\n');
  const itemId = await saveItem(null, {
    kind: 'note',
    name,
    notes: notes || null,
    favorite: false,
    reprompt: false,
    folderId: null,
    fields: [],
  });
  for (const file of arrived.files) {
    const sealed = await callJson<{ fileName: string; key: string }>((core) =>
      core.takeSubmissionFile(JSON.stringify(arrived.stored), file.id, itemId),
    );
    await request(`${submissionPath(arrived)}/files/${id(file.id)}/attach`, {
      body: { cipherId: itemId, ...sealed },
    });
  }
  await deleteArrived(arrived);
  await sync();
  return itemId;
}

// ── The uploader's side ───────────────────────────────────

export type OpenedRequest = {
  title: string;
  note: string | null;
  owner: string | null;
  maxFiles: number;
  maxFileBytes: number;
  textAllowed: boolean;
  expirationDate: string;
  token: string;
  publicInfo: string;
};

const publicPath = (accessId: string) => `/uwu/v1/public/file-requests/${id(accessId)}`;

/** Whether the link still takes uploads, and whether it needs a password. */
export async function requestAccess(accessId: string): Promise<{ passwordRequired: boolean }> {
  return request(publicPath(accessId), { auth: false });
}

/** Opens the link (with its password, if it has one). Throws `{ kind: 'password' }` for a wrong one. */
export async function openRequest(
  accessId: string,
  secret: string,
  password?: string,
): Promise<OpenedRequest> {
  const passwordHash = password
    ? await call((core) => core.fileRequestPassword(password, secret))
    : null;
  let answer: Record<string, unknown>;
  try {
    answer = await request(`${publicPath(accessId)}/open`, {
      body: { passwordHash },
      auth: false,
    });
  } catch (error) {
    const code = ((error as ApiError).body as { code?: string } | null)?.code;
    if (code === 'password_required' || code === 'password_invalid')
      throw { kind: 'password', message: code };
    throw error;
  }
  await load();
  const upload = new Upload(String(answer.publicInfo), secret);
  const info = JSON.parse(upload.info()) as {
    title: string;
    note: string | null;
    owner: string | null;
  };
  upload.free();
  return {
    ...info,
    maxFiles: Number(answer.maxFiles),
    maxFileBytes: Number(answer.maxFileBytes),
    textAllowed: Boolean(answer.textAllowed),
    expirationDate: String(answer.expirationDate),
    token: String(answer.token),
    publicInfo: String(answer.publicInfo),
  };
}

/** A put with the upload token, the encrypted file as the body. */
async function put(path: string, token: string, data: Uint8Array): Promise<void> {
  const response = await fetch(path, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/octet-stream' },
    body: data as BodyInit,
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { message?: string } | null;
    throw new ApiError(response.status, body?.message ?? `HTTP ${response.status}`, body);
  }
}

/**
 * Encrypts and sends a submission: the message, who sent it, the files. `progress` hears how
 * many files are up.
 */
export async function submit(
  accessId: string,
  secret: string,
  opened: OpenedRequest,
  what: { text: string; name: string; email: string; files: File[] },
  progress: (done: number) => void,
): Promise<void> {
  await load();
  const upload = new Upload(opened.publicInfo, secret);
  try {
    const sealed = JSON.parse(
      upload.seal(what.text, what.name, what.email, JSON.stringify(what.files.map((f) => f.name))),
    ) as { files: { fileName: string; key: string }[] } & Record<string, unknown>;
    const encrypted: Uint8Array[] = [];
    for (const [index, file] of what.files.entries()) {
      encrypted.push(upload.encryptFile(index, new Uint8Array(await file.arrayBuffer())));
    }
    const body = {
      ...sealed,
      files: sealed.files.map((file, index) => ({ ...file, size: encrypted[index]!.length })),
    };
    const started = await request<{ id: string; files: { id: string; url: string }[] }>(
      `${publicPath(accessId)}/submissions`,
      { body, auth: false, extraHeaders: { Authorization: `Bearer ${opened.token}` } },
    );
    for (const [index, file] of started.files.entries()) {
      await put(file.url, opened.token, encrypted[index]!);
      progress(index + 1);
    }
    await request(`${publicPath(accessId)}/submissions/${id(started.id)}/complete`, {
      body: {},
      auth: false,
      extraHeaders: { Authorization: `Bearer ${opened.token}` },
    });
  } finally {
    upload.free();
  }
}
