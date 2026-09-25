// Registers an account the way a Bitwarden client does, with nothing but Node's own crypto:
// the master key from the password, a user key wrapped under it, an RSA key pair wrapped under
// the user key. For tests that need an account without a browser.
//
//   node scripts/e2e/register.mjs <server> <invitation link or token> <email> <password>

import { createCipheriv, createHmac, generateKeyPairSync, pbkdf2Sync, randomBytes } from 'node:crypto';

const [server, invitation, email, password] = process.argv.slice(2);
if (!password) {
  console.error('usage: register.mjs <server> <invitation link or token> <email> <password>');
  process.exit(2);
}
const token = invitation.includes('token=') ? new URL(invitation.replace('/#/', '/')).searchParams.get('token') : invitation;
const salt = email.trim().toLowerCase();
const iterations = 600000;

const masterKey = pbkdf2Sync(password, salt, iterations, 32, 'sha256');
const masterPasswordHash = pbkdf2Sync(masterKey, password, 1, 32, 'sha256').toString('base64');
// HKDF-Expand only, as Bitwarden stretches: one block per key.
const expand = (info) => createHmac('sha256', masterKey).update(Buffer.concat([Buffer.from(info), Buffer.from([1])])).digest();

function encrypt(plain, encKey, macKey) {
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc', encKey, iv);
  const data = Buffer.concat([cipher.update(plain), cipher.final()]);
  const mac = createHmac('sha256', macKey).update(Buffer.concat([iv, data])).digest();
  return `2.${iv.toString('base64')}|${data.toString('base64')}|${mac.toString('base64')}`;
}

const userKey = randomBytes(64);
const protectedKey = encrypt(userKey, expand('enc'), expand('mac'));
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicDer = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const privateDer = privateKey.export({ type: 'pkcs8', format: 'der' });
const encryptedPrivateKey = encrypt(privateDer, userKey.subarray(0, 32), userKey.subarray(32));

const response = await fetch(`${server}/identity/accounts/register/finish`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    email,
    name: email.split('@')[0],
    masterPasswordHash,
    masterPasswordHint: null,
    key: protectedKey,
    kdf: 0,
    kdfIterations: iterations,
    keys: { publicKey: publicDer, encryptedPrivateKey },
    emailVerificationToken: token,
  }),
});
if (!response.ok) {
  console.error(`registering failed: HTTP ${response.status} ${await response.text()}`);
  process.exit(1);
}
console.log(`registered ${email}`);
