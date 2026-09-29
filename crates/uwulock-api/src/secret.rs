//! The server's secret for values at rest lives in `uwulock-store`, where the off-site backups
//! reach it too.

pub use uwulock_store::secret::*;

/// Set to make a new `secret.key` although sealed values exist: they are lost then, and the
/// admin enters them again (SSO client secret, channel tokens, the passwords of the mail server,
/// Loki and the off-site backups; masked addresses connect again).
pub const NEW_KEY_VARIABLE: &str = "UWULOCK_NEW_SECRET_KEY";

/// Refuses to start when the database holds sealed values but `secret.key` is gone: a new key
/// would be made quietly and every one of them fail with a bare 500 (SV-I1).
pub async fn check_key(store: &uwulock_store::Store, secret: &ServerSecret) -> Result<(), String> {
    if secret.exists() {
        return Ok(());
    }
    let sealed = store.sealed_values().await.map_err(|error| error.to_string())?;
    if sealed == 0 {
        return Ok(());
    }
    if std::env::var_os(NEW_KEY_VARIABLE).is_some_and(|value| value == "1") {
        tracing::warn!(sealed, "secret.key is missing; a new one is made and the sealed values are emptied");
        return store.forget_sealed_values().await.map_err(|error| error.to_string());
    }
    Err(format!(
        "{FILE} is missing from the data directory, but {sealed} values in the database are sealed with it. \
         Put it back from a backup of the data directory. If it is lost for good, start once with \
         {NEW_KEY_VARIABLE}=1 and enter the SSO client secret, the channel tokens and the passwords of the \
         mail server, Loki and the off-site backups again."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_start_without_the_key_to_what_is_sealed() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            uwulock_store::Store::open_sqlite(&dir.path().join("db"), &uwulock_store::Options { readers: 1 }).unwrap();
        let secret = ServerSecret::new(dir.path());
        assert!(check_key(&store, &secret).await.is_ok(), "nothing sealed yet");
        let sealed = secret.seal("smtp-geheim", "settings.smtp.password").unwrap();
        store
            .set_setting("settings", &serde_json::json!({ "smtp": { "password": sealed } }).to_string())
            .await
            .unwrap();
        assert!(check_key(&store, &secret).await.is_ok());

        std::fs::remove_file(dir.path().join(FILE)).unwrap();
        let without = ServerSecret::new(dir.path());
        let refused = check_key(&store, &without).await.unwrap_err();
        assert!(refused.contains("secret.key") && refused.contains(NEW_KEY_VARIABLE), "{refused}");

        // Lost for good: the sealed values are emptied, the rest stays.
        store.forget_sealed_values().await.unwrap();
        assert_eq!(store.sealed_values().await.unwrap(), 0);
        assert_eq!(store.setting("settings").await.unwrap().unwrap(), r#"{"smtp":{"password":""}}"#);
        assert!(check_key(&store, &without).await.is_ok());
    }
}
