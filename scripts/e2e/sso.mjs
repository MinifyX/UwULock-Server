// Logging in through SSO (docs/sso.md), in a real browser against a running UwULock Server, with
// an OpenID Connect provider of its own on this machine that says yes to whoever it is told:
// the admin sets the provider up in the admin portal; somebody new signs up through it and sets
// the master password; the admin logs in to the portal through it; and a Bitwarden client's
// login that opens the web vault at `#/sso?clientId=browser` goes through to the connector page.
//
//   node scripts/e2e/sso.mjs <origin> <admin email> <admin password> [screenshot directory]

import {
    createHash,
    createSign,
    generateKeyPairSync,
    randomBytes,
} from "node:crypto";
import { mkdirSync } from "node:fs";
import { createServer } from "node:http";
import { chromium } from "playwright";

const [origin, email, password, shots] = process.argv.slice(2);
if (!origin || !email || !password) {
    console.error(
        "usage: sso.mjs <origin> <admin email> <admin password> [screenshot directory]",
    );
    process.exit(2);
}
if (shots) mkdirSync(shots, { recursive: true });

// ── The provider ──────────────────────────────────────────

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
});
const jwk = {
    ...publicKey.export({ format: "jwk" }),
    kid: "k1",
    alg: "RS256",
    use: "sig",
};
const b64url = (data) => Buffer.from(data).toString("base64url");
/** Who the provider logs in next. */
let person = null;
const codes = new Map();

const provider = createServer((request, response) => {
    const url = new URL(request.url, issuer);
    const send = (status, body, headers = {}) => {
        response.writeHead(status, {
            "content-type": "application/json",
            ...headers,
        });
        response.end(typeof body === "string" ? body : JSON.stringify(body));
    };
    if (url.pathname === "/.well-known/openid-configuration") {
        return send(200, {
            issuer,
            authorization_endpoint: `${issuer}/authorize`,
            token_endpoint: `${issuer}/token`,
            jwks_uri: `${issuer}/jwks`,
        });
    }
    if (url.pathname === "/jwks") return send(200, { keys: [jwk] });
    if (url.pathname === "/authorize") {
        // Says yes at once, for whoever `person` is.
        const code = b64url(randomBytes(16));
        codes.set(code, { ...person, nonce: url.searchParams.get("nonce") });
        const back = new URL(url.searchParams.get("redirect_uri"));
        back.searchParams.set("code", code);
        back.searchParams.set("state", url.searchParams.get("state"));
        back.searchParams.set("iss", issuer);
        response.writeHead(302, { location: back.toString() });
        return response.end();
    }
    if (url.pathname === "/token" && request.method === "POST") {
        let body = "";
        request.on("data", (chunk) => (body += chunk));
        request.on("end", () => {
            const form = new URLSearchParams(body);
            const expected = `Basic ${Buffer.from("uwulock:e2e-secret").toString("base64")}`;
            const found = codes.get(form.get("code"));
            codes.delete(form.get("code"));
            if (
                request.headers.authorization !== expected ||
                !found ||
                !form.get("code_verifier")
            ) {
                return send(400, { error: "invalid_grant" });
            }
            const now = Math.floor(Date.now() / 1000);
            const claims = {
                iss: issuer,
                aud: "uwulock",
                exp: now + 300,
                iat: now,
                email_verified: true,
                ...found,
            };
            const signed = `${b64url(JSON.stringify({ alg: "RS256", kid: "k1", typ: "JWT" }))}.${b64url(JSON.stringify(claims))}`;
            const signature = createSign("RSA-SHA256")
                .update(signed)
                .sign(privateKey)
                .toString("base64url");
            send(200, {
                access_token: "e2e",
                token_type: "Bearer",
                id_token: `${signed}.${signature}`,
            });
        });
        return;
    }
    send(404, { error: "not_found" });
});
await new Promise((resolve) => provider.listen(0, "127.0.0.1", resolve));
const issuer = `http://127.0.0.1:${provider.address().port}`;

// ── The browser ───────────────────────────────────────────

const browser = await chromium.launch({
    executablePath: process.env.CHROMIUM || undefined,
    args: process.env.CHROMIUM_ARGS ? process.env.CHROMIUM_ARGS.split(" ") : [],
});
const problems = [];

const pages = [];

async function open(name) {
    const context = await browser.newContext({
        ignoreHTTPSErrors: true,
        viewport: { width: 1280, height: 800 },
        locale: "de-DE",
    });
    const page = await context.newPage();
    pages.push([name, page]);
    page.on("pageerror", (error) =>
        problems.push(`${name}: page error: ${error.message}`),
    );
    page.on("console", (message) => {
        if (
            message.type() === "error" &&
            !message.text().startsWith("Failed to load resource")
        ) {
            problems.push(`${name}: console: ${message.text()}`);
        }
    });
    return page;
}

let shot = 0;
const snap = async (page, name) => {
    if (shots)
        await page.screenshot({
            path: `${shots}/s${String(++shot).padStart(2, "0")}-${name}.png`,
        });
};
const step = (text) => console.log(`== ${text}`);

try {
    step("the admin sets the provider up");
    const admin = await open("admin");
    await admin.goto(`${origin}/admin`);
    await admin
        .getByRole("heading", { name: "Anmelden" })
        .waitFor({ timeout: 30000 });
    await admin.getByLabel("E-Mail-Adresse").fill(email);
    await admin.locator("input[type=password]").first().fill(password);
    await admin.getByRole("button", { name: "Anmelden", exact: true }).click();
    // Sicherheit & Anmeldung → SSO-Anbieter, then → SSO-Regeln; one Speichern takes both.
    await admin
        .locator(".admin-sidebar")
        .getByRole("button", { name: "Sicherheit & Anmeldung" })
        .click();
    await admin.getByRole("tab", { name: "SSO-Anbieter", exact: true }).click();
    await admin.getByLabel("Issuer").fill(issuer);
    await admin.getByLabel("Client-ID").fill("uwulock");
    await admin.getByLabel("Client-Geheimnis").fill("e2e-secret");
    await admin.getByLabel("Beschriftung des Knopfs").fill("Firmen-Login");
    await admin
        .getByRole("switch", { name: "Anmeldung über SSO", exact: true })
        .click();
    await admin.getByRole("button", { name: "Anbieter testen" }).click();
    await admin.getByText(/Der Anbieter antwortet/).waitFor({ timeout: 30000 });
    await admin.getByRole("tab", { name: "SSO-Regeln", exact: true }).click();
    await admin
        .getByLabel("Wer sich ohne Einladung einen Tresor anlegen darf")
        .selectOption("group");
    await admin.getByRole("button", { name: "Speichern", exact: true }).click();
    // Another provider wants the admin's master password (R1-3).
    const confirm = admin.getByRole("dialog");
    await confirm.locator("input[type=password]").fill(password);
    await confirm
        .getByRole("button", { name: "Speichern", exact: true })
        .click();
    await admin.getByText("Gespeichert ✧").waitFor({ timeout: 30000 });
    await snap(admin, "settings");

    step("somebody new signs up through SSO and sets the master password");
    person = { sub: "e2e-mia", email: "mia@example.com", name: "Mia" };
    const mia = await open("mia");
    await mia.goto(origin);
    await mia
        .getByRole("button", { name: "Mit Firmen-Login anmelden" })
        .click();
    await mia
        .getByRole("heading", { name: "Master-Passwort festlegen" })
        .waitFor({ timeout: 30000 });
    await snap(mia, "set-password");
    const fields = mia.locator("input[type=password]");
    await fields.nth(0).fill("mias sehr langes passwort 42");
    await fields.nth(1).fill("mias sehr langes passwort 42");
    await mia.getByRole("button", { name: "Festlegen und öffnen" }).click();
    await mia
        .getByPlaceholder(/Tresor durchsuchen/)
        .waitFor({ timeout: 60000 });
    await snap(mia, "vault");

    step("the admin logs in to the portal through SSO");
    person = { sub: "e2e-admin", email };
    const again = await open("admin-sso");
    await again.goto(`${origin}/admin`);
    await again
        .getByRole("button", { name: "Mit Firmen-Login anmelden" })
        .click();
    // In CI, features.mjs left an authenticator app on the account: the server's own two-step
    // login applies after SSO too, and that is as good an answer here.
    const portal = again.locator(".admin-sidebar");
    const second = again.getByRole("heading", {
        name: "Zweistufige Anmeldung",
    });
    await portal.or(second).first().waitFor({ timeout: 30000 });
    await snap(
        again,
        (await portal.isVisible()) ? "portal" : "portal-second-step",
    );

    step("a Bitwarden extension's login goes through to the connector page");
    person = { sub: "e2e-mia", email: "mia@example.com" };
    const verifier = b64url(randomBytes(40));
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const extension = await open("extension");
    const query = new URLSearchParams({
        clientId: "browser",
        redirectUri: `${origin}/sso-connector.html`,
        state: `e2e-state:clientId=browser`,
        codeChallenge: challenge,
        email: "mia@example.com",
    });
    await extension.goto(`${origin}/#/sso?${query}`);
    await extension
        .getByText(/Die Erweiterung übernimmt jetzt/)
        .waitFor({ timeout: 30000 });
    const code = new URL(extension.url()).searchParams.get("code");
    if (!code)
        throw new Error(`no code on the connector page: ${extension.url()}`);
    const token = await fetch(`${origin}/identity/connect/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            code_verifier: verifier,
            redirect_uri: `${origin}/sso-connector.html`,
            client_id: "browser",
            scope: "api offline_access",
            deviceType: "2",
            deviceIdentifier: "e2e-extension",
            deviceName: "chrome",
        }),
    });
    const answer = await token.json();
    if (token.status !== 200 || !answer.Key)
        throw new Error(`the token: ${token.status} ${JSON.stringify(answer)}`);
} catch (error) {
    console.error(error);
    problems.push(String(error));
    // What each page showed when it failed.
    for (const [name, page] of pages) {
        const text = await page
            .locator("body")
            .innerText({ timeout: 2000 })
            .catch(() => "?");
        console.error(`-- ${name} at ${page.url()}:\n${text.slice(0, 600)}`);
        await snap(page, `failed-${name}`).catch(() => undefined);
    }
} finally {
    await browser.close();
    provider.close();
}

if (problems.length > 0) {
    console.error(problems.join("\n"));
    process.exit(1);
}
console.log("SSO in the browser: fine");
