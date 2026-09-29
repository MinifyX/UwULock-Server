//! Talking to a UwUMail server for masked addresses: OAuth (RFC 8414 discovery, RFC 7591
//! registration, the code and refresh grants, RFC 7009 revocation) and JMAP `MaskedEmail`.
//!
//! Only servers an admin listed are asked, only on the origin they were listed with — every
//! endpoint a discovery document or a JMAP session names has to be on it — and no redirect is
//! followed ([`crate::outbound::client`]). An admin-listed server may be on a private address;
//! nothing else is ever contacted.

use serde_json::{Value, json};

/// The JMAP capability of masked addresses.
pub(crate) const CAPABILITY: &str = "https://www.fastmail.com/dev/maskedemail";
/// The OAuth scope UwUMail has for them alone.
pub(crate) const SCOPE: &str = "maskedemail";

/// What went wrong with a call to UwUMail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Upstream {
    /// An OAuth error answer: `invalid_grant`, `invalid_client`, …
    Refused { status: u16, error: String },
    /// 429.
    RateLimited,
    /// No answer, or one this server does not understand.
    Failed(String),
}

impl Upstream {
    pub(crate) fn text(&self) -> String {
        match self {
            Upstream::Refused { status, error } => format!("UwUMail refused it ({status} {error})"),
            Upstream::RateLimited => "UwUMail asks to wait (too many requests)".into(),
            Upstream::Failed(error) => error.clone(),
        }
    }

    pub(crate) fn is(&self, code: &str) -> bool {
        matches!(self, Upstream::Refused { error, .. } if error == code)
    }
}

/// `https://mail.example.com` of a URL, lower case: what "the same origin" compares.
fn origin(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    Some(parsed.origin().ascii_serialization().to_ascii_lowercase())
}

/// `url`, when it is on `server`'s origin; an error naming what it is otherwise.
fn on_server(server: &str, url: Option<&str>, what: &str) -> Result<String, Upstream> {
    let url = url.ok_or_else(|| Upstream::Failed(format!("UwUMail names no {what}")))?;
    if origin(url).is_none() || origin(url) != origin(server) {
        return Err(Upstream::Failed(format!("UwUMail's {what} {url} is not on {server}; it is not used")));
    }
    Ok(url.to_string())
}

fn failed(error: &reqwest::Error) -> Upstream {
    Upstream::Failed(format!("UwUMail does not answer: {}", crate::outbound::error_text(error)))
}

/// A response's body as JSON, or the reason it is not a success.
async fn answer(response: reqwest::Response) -> Result<Value, Upstream> {
    let status = response.status();
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(Upstream::RateLimited);
    }
    if status.is_redirection() {
        return Err(Upstream::Failed(crate::outbound::refused(response).await));
    }
    let bytes = response.bytes().await.map_err(|error| failed(&error))?;
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if status.is_success() {
        return Ok(body);
    }
    match body["error"].as_str() {
        Some(error) => Err(Upstream::Refused { status: status.as_u16(), error: error.to_string() }),
        None => Err(Upstream::Refused { status: status.as_u16(), error: format!("status {}", status.as_u16()) }),
    }
}

// ── OAuth ─────────────────────────────────────────────────

fn form_body(fields: &[(&str, &str)]) -> String {
    let encode = crate::oidc::form_encode;
    fields.iter().map(|(key, value)| format!("{}={}", encode(key), encode(value))).collect::<Vec<_>>().join("&")
}

#[derive(Debug, Clone)]
pub(crate) struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: String,
    pub revocation_endpoint: Option<String>,
}

/// `<server>/.well-known/oauth-authorization-server`, checked: every endpoint on the server's
/// origin, the issuer the server itself (RFC 8414 §3.3), and the `maskedemail` scope offered.
pub(crate) async fn discover(server: &str) -> Result<Discovery, Upstream> {
    let client = crate::outbound::client().map_err(Upstream::Failed)?;
    let response = client
        .get(format!("{server}/.well-known/oauth-authorization-server"))
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| failed(&error))?;
    let body = answer(response).await?;
    let issuer = body["issuer"].as_str().unwrap_or_default().trim_end_matches('/').to_string();
    if !issuer.eq_ignore_ascii_case(server) {
        return Err(Upstream::Failed(format!("UwUMail calls itself {issuer}, not {server}")));
    }
    let scopes = body["scopes_supported"].as_array().cloned().unwrap_or_default();
    if !scopes.iter().any(|scope| scope == SCOPE) {
        return Err(Upstream::Failed(
            "This UwUMail server has no scope for masked addresses (maskedemail): it needs an update.".into(),
        ));
    }
    let revocation = body["revocation_endpoint"].as_str();
    Ok(Discovery {
        issuer: body["issuer"].as_str().unwrap_or_default().to_string(),
        authorization_endpoint: on_server(server, body["authorization_endpoint"].as_str(), "authorization endpoint")?,
        token_endpoint: on_server(server, body["token_endpoint"].as_str(), "token endpoint")?,
        registration_endpoint: on_server(server, body["registration_endpoint"].as_str(), "registration endpoint")?,
        revocation_endpoint: revocation.map(|url| on_server(server, Some(url), "revocation endpoint")).transpose()?,
    })
}

/// Register as a public client (RFC 7591); the client id.
pub(crate) async fn register(discovery: &Discovery, name: &str, redirect_uri: &str) -> Result<String, Upstream> {
    let client = crate::outbound::client().map_err(Upstream::Failed)?;
    let response = client
        .post(&discovery.registration_endpoint)
        .json(&json!({ "client_name": name, "redirect_uris": [redirect_uri] }))
        .send()
        .await
        .map_err(|error| failed(&error))?;
    let body = answer(response).await?;
    body["client_id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Upstream::Failed("UwUMail registered no client id".into()))
}

/// What the token endpoint hands out.
#[derive(Debug, Clone)]
pub(crate) struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
    /// Seconds.
    pub expires_in: i64,
}

async fn token_request(endpoint: &str, form: &[(&str, &str)]) -> Result<Tokens, Upstream> {
    let client = crate::outbound::client().map_err(Upstream::Failed)?;
    let response = client
        .post(endpoint)
        .header("accept", "application/json")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form_body(form))
        .send()
        .await
        .map_err(|error| failed(&error))?;
    let body = answer(response).await?;
    let text = |key: &str| body[key].as_str().filter(|value| !value.is_empty()).map(str::to_string);
    let scope = body["scope"].as_str().unwrap_or(SCOPE);
    if !scope.split(' ').any(|granted| granted == SCOPE) {
        // UwUMail drops the scope when JMAP is off for the account.
        return Err(Upstream::Refused { status: 400, error: "invalid_scope".into() });
    }
    match (text("access_token"), text("refresh_token")) {
        (Some(access_token), Some(refresh_token)) => {
            Ok(Tokens { access_token, refresh_token, expires_in: body["expires_in"].as_i64().unwrap_or(3600) })
        }
        _ => Err(Upstream::Failed("UwUMail's token answer lacks a token".into())),
    }
}

/// The code from the callback, for tokens (PKCE).
pub(crate) async fn exchange(
    endpoint: &str,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Result<Tokens, Upstream> {
    token_request(
        endpoint,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", verifier),
        ],
    )
    .await
}

/// A new access token, and the new refresh token that replaces `refresh_token` from now on.
pub(crate) async fn refresh(endpoint: &str, client_id: &str, refresh_token: &str) -> Result<Tokens, Upstream> {
    token_request(
        endpoint,
        &[("grant_type", "refresh_token"), ("refresh_token", refresh_token), ("client_id", client_id)],
    )
    .await
}

/// End the grant (RFC 7009). Best effort: UwUMail always answers 200.
pub(crate) async fn revoke(endpoint: &str, client_id: &str, token: &str) -> Result<(), Upstream> {
    let client = crate::outbound::client().map_err(Upstream::Failed)?;
    let response = client
        .post(endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form_body(&[("token", token), ("client_id", client_id)]))
        .send()
        .await
        .map_err(|error| failed(&error))?;
    answer(response).await.map(|_| ())
}

// ── JMAP ──────────────────────────────────────────────────

/// What the JMAP session says about masked addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Session {
    pub api_url: String,
    pub account_id: String,
    pub username: String,
    pub domains: Vec<String>,
    pub default_domain: Option<String>,
}

/// `<server>/jmap/session` with the access token.
pub(crate) async fn session(server: &str, access_token: &str) -> Result<Session, Upstream> {
    let client = crate::outbound::client().map_err(Upstream::Failed)?;
    let response = client
        .get(format!("{server}/jmap/session"))
        .bearer_auth(access_token)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| failed(&error))?;
    let body = answer(response).await?;
    let account_id = body["primaryAccounts"][CAPABILITY]
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| Upstream::Failed("UwUMail's session has no account for masked addresses".into()))?
        .to_string();
    let capability = &body["accounts"][&account_id]["accountCapabilities"][CAPABILITY];
    let domains = capability["domains"]
        .as_array()
        .map(|domains| domains.iter().filter_map(Value::as_str).map(str::to_ascii_lowercase).collect())
        .unwrap_or_default();
    Ok(Session {
        api_url: on_server(server, body["apiUrl"].as_str(), "JMAP address")?,
        account_id,
        username: body["username"].as_str().unwrap_or_default().to_string(),
        domains,
        default_domain: capability["defaultDomain"].as_str().map(str::to_ascii_lowercase),
    })
}

/// A JMAP method that did not work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Call {
    /// The HTTP request did not work; 401 means the access token is not taken (any more).
    Http(Upstream),
    /// A JMAP method error (`forbidden`, `accountNotFound`, …) with its description.
    Method(String, String),
}

/// One method call; its arguments.
pub(crate) async fn call(api_url: &str, access_token: &str, method: &str, arguments: Value) -> Result<Value, Call> {
    let client = crate::outbound::client().map_err(|error| Call::Http(Upstream::Failed(error)))?;
    let response = client
        .post(api_url)
        .bearer_auth(access_token)
        .json(&json!({
            "using": ["urn:ietf:params:jmap:core", CAPABILITY],
            "methodCalls": [[method, arguments, "0"]],
        }))
        .send()
        .await
        .map_err(|error| Call::Http(failed(&error)))?;
    let body = answer(response).await.map_err(Call::Http)?;
    let first = &body["methodResponses"][0];
    match first[0].as_str() {
        Some("error") => Err(Call::Method(
            first[1]["type"].as_str().unwrap_or("serverFail").to_string(),
            first[1]["description"].as_str().unwrap_or_default().to_string(),
        )),
        Some(name) if name == method => Ok(first[1].clone()),
        _ => Err(Call::Http(Upstream::Failed("UwUMail's JMAP answer is not understood".into()))),
    }
}

/// What the admin portal's check of a server shows: whether discovery works, whether it offers
/// the `maskedemail` scope, whether apps can register there; the first problem in words.
pub(crate) async fn inspect(server: &str) -> Value {
    let found = async {
        let client = crate::outbound::client().map_err(Upstream::Failed)?;
        let response = client
            .get(format!("{server}/.well-known/oauth-authorization-server"))
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|error| failed(&error))?;
        answer(response).await
    }
    .await;
    let body = match found {
        Ok(body) if body["issuer"].is_string() => body,
        Ok(_) => {
            return json!({ "discovery": false, "maskedScope": false, "registration": false,
                "error": "The answer is no OAuth discovery document. Is this a UwUMail server?" });
        }
        Err(error) => {
            return json!({ "discovery": false, "maskedScope": false, "registration": false, "error": error.text() });
        }
    };
    let scope = body["scopes_supported"].as_array().is_some_and(|scopes| scopes.iter().any(|scope| scope == SCOPE));
    let registration = on_server(server, body["registration_endpoint"].as_str(), "registration endpoint");
    let issuer = body["issuer"].as_str().unwrap_or_default().trim_end_matches('/');
    let error = if !issuer.eq_ignore_ascii_case(server) {
        Some(format!("UwUMail calls itself {issuer}; list it under that address."))
    } else if !scope {
        Some("This UwUMail server has no scope for masked addresses (maskedemail): it needs an update.".to_string())
    } else {
        registration.as_ref().err().map(Upstream::text)
    };
    json!({ "discovery": true, "maskedScope": scope, "registration": registration.is_ok(), "error": error })
}
