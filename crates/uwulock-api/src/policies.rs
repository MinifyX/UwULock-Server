//! Server policies for every account (docs/uwu-api.md §20): two-step login required after a
//! deadline, a minimum key derivation, and rules for the master password.
//!
//! The server sees the KDF settings, so it enforces those itself. It never sees the master
//! password, so its rules only reach the clients: the web vault checks them, and the official
//! clients get them as Bitwarden's `MasterPasswordPolicy` in the token response, which they
//! honour at registration, at a password change and — with `enforceOnLogin` — right after login.

use crate::errors::{ApiError, ApiResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uwulock_store::{Kdf, clock};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Policies {
    pub require_two_factor: RequireTwoFactor,
    pub minimum_kdf: MinimumKdf,
    pub master_password: MasterPasswordRules,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RequireTwoFactor {
    pub enabled: bool,
    /// From when on accounts without two-step login only get into the web vault, to set it up.
    /// None: at once.
    pub deadline: Option<String>,
}

/// The weakest key derivation the server takes. Bitwarden's defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MinimumKdf {
    pub pbkdf2_iterations: i64,
    /// MiB.
    pub argon2_memory: i64,
    pub argon2_iterations: i64,
    pub argon2_parallelism: i64,
}

impl Default for MinimumKdf {
    fn default() -> Self {
        MinimumKdf { pbkdf2_iterations: 600_000, argon2_memory: 64, argon2_iterations: 3, argon2_parallelism: 4 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MasterPasswordRules {
    pub min_length: u32,
    /// A zxcvbn score from 0 to 4; 0 asks for nothing.
    pub min_complexity: u8,
    /// The official clients make a person with a weaker password change it after login.
    pub enforce_on_login: bool,
}

impl Default for MasterPasswordRules {
    fn default() -> Self {
        // Bitwarden's clients ask for 12 characters anyway.
        MasterPasswordRules { min_length: 12, min_complexity: 0, enforce_on_login: false }
    }
}

impl Policies {
    pub fn check(&self) -> Result<(), String> {
        if let Some(deadline) = &self.require_two_factor.deadline
            && clock::parse(deadline).is_none()
        {
            return Err("The deadline for two-step login is not a date.".into());
        }
        let kdf = &self.minimum_kdf;
        if !(100_000..=2_000_000).contains(&kdf.pbkdf2_iterations) {
            return Err("The minimum PBKDF2 iterations can be from 100000 to 2000000.".into());
        }
        if !(15..=1024).contains(&kdf.argon2_memory)
            || !(2..=10).contains(&kdf.argon2_iterations)
            || !(1..=16).contains(&kdf.argon2_parallelism)
        {
            return Err(
                "The minimum Argon2 settings can be 15 to 1024 MB, 2 to 10 iterations and a parallelism of 1 to 16."
                    .into(),
            );
        }
        let rules = &self.master_password;
        if rules.min_length > 128 || rules.min_complexity > 4 {
            return Err("A master password can be asked to have up to 128 characters and a strength up to 4.".into());
        }
        Ok(())
    }

    /// Whether `kdf` is weaker than the minimum.
    pub fn kdf_below_minimum(&self, kdf: &Kdf) -> bool {
        let minimum = &self.minimum_kdf;
        match kdf.kind {
            0 => kdf.iterations < minimum.pbkdf2_iterations,
            _ => {
                kdf.iterations < minimum.argon2_iterations
                    || kdf.memory.unwrap_or(0) < minimum.argon2_memory
                    || kdf.parallelism.unwrap_or(0) < minimum.argon2_parallelism
            }
        }
    }

    /// Refuses a new key derivation that is weaker than the minimum, saying what the minimum is.
    pub fn check_kdf(&self, kdf: &Kdf) -> ApiResult<()> {
        if !self.kdf_below_minimum(kdf) {
            return Ok(());
        }
        let minimum = &self.minimum_kdf;
        let message = match kdf.kind {
            0 => format!(
                "This server asks for at least {} PBKDF2 iterations. Choose more, or Argon2id.",
                minimum.pbkdf2_iterations
            ),
            _ => format!(
                "This server asks for Argon2id with at least {} MB of memory, {} iterations and a parallelism of {}.",
                minimum.argon2_memory, minimum.argon2_iterations, minimum.argon2_parallelism
            ),
        };
        Err(ApiError::bad(message).code("kdf_too_weak"))
    }

    /// Whether an account without two-step login is shut out of everything but the web vault
    /// now: the policy is on, and its deadline (if it has one) has passed.
    pub fn two_factor_enforced(&self) -> bool {
        self.require_two_factor.enabled
            && self
                .require_two_factor
                .deadline
                .as_deref()
                .and_then(clock::parse)
                .is_none_or(|deadline| deadline <= time::OffsetDateTime::now_utc())
    }

    /// Bitwarden's `MasterPasswordPolicy` of a token response.
    pub fn master_password_policy(&self) -> Value {
        let rules = &self.master_password;
        json!({
            "MinComplexity": rules.min_complexity,
            "MinLength": rules.min_length,
            "RequireUpper": false,
            "RequireLower": false,
            "RequireNumbers": false,
            "RequireSpecial": false,
            "EnforceOnLogin": rules.enforce_on_login,
            "Object": "masterPasswordPolicy",
        })
    }
}

/// The client id of UwULock's web vault: the only one that still gets a token while two-step
/// login is required and missing, so its owner can set it up.
pub const WEB_VAULT: &str = "web";

/// What `/identity/connect/token` answers another client of an account that has to set up
/// two-step login first. The official clients show `ErrorModel.Message`.
pub fn two_factor_required(public: &str) -> ApiError {
    let message =
        format!("This server requires two-step login. Set it up in the web vault at {public}, then log in again.");
    ApiError::json(json!({
        "error": "invalid_grant",
        "error_description": "two_factor_required",
        "ErrorModel": { "Message": message, "Object": "error" },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Settings;
    use crate::test_support::*;
    use axum::http::StatusCode;

    fn pbkdf2(iterations: i64) -> Kdf {
        Kdf { kind: 0, iterations, memory: None, parallelism: None }
    }

    fn argon2(memory: i64, iterations: i64, parallelism: i64) -> Kdf {
        Kdf { kind: 1, iterations, memory: Some(memory), parallelism: Some(parallelism) }
    }

    #[test]
    fn weaker_key_derivations_are_found() {
        let policies = Policies::default();
        assert!(policies.kdf_below_minimum(&pbkdf2(100_000)), "Vaultwarden's old default");
        assert!(!policies.kdf_below_minimum(&pbkdf2(600_000)));
        assert!(!policies.kdf_below_minimum(&argon2(64, 3, 4)));
        assert!(policies.kdf_below_minimum(&argon2(32, 3, 4)));
        assert!(policies.kdf_below_minimum(&argon2(64, 2, 4)));
        let error = policies.check_kdf(&pbkdf2(100_000)).unwrap_err();
        assert!(error.message().contains("600000"), "{}", error.message());
    }

    #[test]
    fn two_step_login_is_enforced_from_the_deadline() {
        let mut policies = Policies::default();
        assert!(!policies.two_factor_enforced());
        policies.require_two_factor.enabled = true;
        assert!(policies.two_factor_enforced(), "no deadline: at once");
        policies.require_two_factor.deadline = Some(clock::in_seconds(3600));
        assert!(!policies.two_factor_enforced());
        policies.require_two_factor.deadline = Some(clock::in_seconds(-1));
        assert!(policies.two_factor_enforced());
    }

    #[test]
    fn settings_that_make_no_sense_are_refused() {
        assert!(Policies::default().check().is_ok());
        let mut policies = Policies::default();
        policies.minimum_kdf.pbkdf2_iterations = 5000;
        assert!(policies.check().is_err());
        let mut policies = Policies::default();
        policies.require_two_factor.deadline = Some("soon".into());
        assert!(policies.check().is_err());
        let mut policies = Policies::default();
        policies.master_password.min_complexity = 5;
        assert!(policies.check().is_err());
    }

    fn strict() -> Policies {
        Policies {
            master_password: MasterPasswordRules { min_length: 14, min_complexity: 3, enforce_on_login: true },
            ..Policies::default()
        }
    }

    #[tokio::test]
    async fn the_official_clients_get_bitwarden_s_policy_at_login() {
        let server = TestServer::with_settings(Settings { policies: strict(), ..Settings::default() }).await;
        server.account("nyu@example.com").await;
        let response = server.form("/identity/connect/token", &login_form("nyu@example.com", "d2")).await;
        let policy = json(response).await["MasterPasswordPolicy"].clone();
        assert_eq!(policy["MinLength"], 14);
        assert_eq!(policy["MinComplexity"], 3);
        assert_eq!(policy["EnforceOnLogin"], true);
        assert_eq!(policy["Object"], "masterPasswordPolicy");
        let info = json(server.get("/uwu/v1/info").await).await;
        assert_eq!(info["policies"]["masterPassword"]["minLength"], 14);
    }

    #[tokio::test]
    async fn after_the_deadline_only_the_web_vault_lets_an_account_without_two_step_login_in() {
        let mut policies = Policies {
            require_two_factor: RequireTwoFactor { enabled: true, deadline: Some(clock::in_seconds(3600)) },
            ..Policies::default()
        };
        let server = TestServer::with_settings(Settings { policies: policies.clone(), ..Settings::default() }).await;
        let account = server.account("nyu@example.com").await;
        let me = json(server.get_as(&account.token, "/uwu/v1/account").await).await;
        assert_eq!(me["policy"]["twoFactorRequired"], true);
        assert_eq!(me["policy"]["twoFactorEnforced"], false, "before the deadline");

        policies.require_two_factor.deadline = Some(clock::in_seconds(-1));
        server.state.apply_settings(Settings { policies, ..Settings::default() });
        let refused = server.form("/identity/connect/token", &login_form("nyu@example.com", "d2")).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        let body = json(refused).await;
        assert_eq!(body["error_description"], "two_factor_required");
        assert!(body["ErrorModel"]["Message"].as_str().unwrap().contains("https://vault.example.com"));
        let refresh =
            [("grant_type", "refresh_token"), ("client_id", "browser"), ("refresh_token", account.refresh.as_str())];
        assert_eq!(server.form("/identity/connect/token", &refresh).await.status(), StatusCode::BAD_REQUEST);

        let mut web = login_form("nyu@example.com", "d3");
        web[4].1 = "web";
        let response = server.form("/identity/connect/token", &web).await;
        assert_eq!(response.status(), StatusCode::OK, "the web vault, to set it up");
        let token = json(response).await["access_token"].as_str().unwrap().to_string();
        let me = json(server.get_as(&token, "/uwu/v1/account").await).await;
        assert_eq!(me["policy"]["twoFactorEnforced"], true);
    }

    #[tokio::test]
    async fn a_weaker_key_derivation_is_refused_and_an_old_one_noticed() {
        let server = TestServer::new().await;
        let token = server.invite("weak@example.com", false).await;
        let mut body = register_body("weak@example.com", &token);
        body["kdfIterations"] = serde_json::json!(100_000);
        let refused = server.call("POST", "/identity/accounts/register/finish", None, body).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json(refused).await["code"], "kdf_too_weak");

        // An account from Vaultwarden, from before the minimum: listed, once, and it may switch.
        let account = server.account("nyu@example.com").await;
        server
            .state
            .store
            .update_user(&account.id, |user| {
                user.kdf = Kdf { kind: 0, iterations: 100_000, memory: None, parallelism: None }
            })
            .await
            .unwrap();
        server.login("nyu@example.com", "d2").await;
        let again = server.login("nyu@example.com", "d3").await;
        let notices = server.state.store.notices(&account.id, None, 50).await.unwrap();
        assert_eq!(notices.iter().filter(|notice| notice.kind == "kdfBelowMinimum").count(), 1);
        let me = json(server.get_as(&again.token, "/uwu/v1/account").await).await;
        assert_eq!(me["policy"]["kdfBelowMinimum"], true);

        let change = |iterations: i64| {
            serde_json::json!({
                "masterPasswordHash": password_hash("nyu@example.com"),
                "newMasterPasswordHash": password_hash("nyu@example.com"),
                "key": "2.k|k|k",
                "kdf": 0,
                "kdfIterations": iterations,
            })
        };
        let weak = server.call("POST", "/api/accounts/kdf", Some(&again.token), change(200_000)).await;
        assert_eq!(weak.status(), StatusCode::BAD_REQUEST);
        let strong = server.call("POST", "/api/accounts/kdf", Some(&again.token), change(700_000)).await;
        assert_eq!(strong.status(), StatusCode::OK);
        let notices = server.state.store.notices(&account.id, None, 50).await.unwrap();
        assert!(notices.iter().any(|notice| notice.kind == "kdfChanged"));
    }
}
