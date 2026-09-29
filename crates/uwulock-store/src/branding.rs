//! The server's own look: a name, an accent colour, logos for light and dark, a favicon. Kept in
//! the database, so it is in every backup. `scope` is `""` for the server; a send domain's id for
//! that domain's own (Stufe 6).

use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, params};

/// The scope of the server's own branding.
pub const SERVER: &str = "";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Branding {
    pub scope: String,
    pub name: Option<String>,
    /// `#rrggbb`, lower case.
    pub color: Option<String>,
    /// PNG, as the server re-encoded it.
    pub logo_light: Option<Vec<u8>>,
    pub logo_dark: Option<Vec<u8>>,
    pub favicon: Option<Vec<u8>>,
    pub revision: String,
}

impl Branding {
    /// Whether anything differs from UwULock's own look.
    pub fn custom(&self) -> bool {
        self.name.is_some()
            || self.color.is_some()
            || self.logo_light.is_some()
            || self.logo_dark.is_some()
            || self.favicon.is_some()
    }
}

/// One of the pictures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Image {
    LogoLight,
    LogoDark,
    Favicon,
}

impl Image {
    fn column(self) -> &'static str {
        match self {
            Image::LogoLight => "logo_light",
            Image::LogoDark => "logo_dark",
            Image::Favicon => "favicon",
        }
    }
}

impl Store {
    /// The branding of `scope`; nothing when it was never changed.
    pub async fn branding(&self, scope: &str) -> Result<Option<Branding>> {
        let scope = scope.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT scope, name, color, logo_light, logo_dark, favicon, revision FROM branding WHERE scope = ?1",
                [scope],
                |row| {
                    Ok(Branding {
                        scope: row.get(0)?,
                        name: row.get(1)?,
                        color: row.get(2)?,
                        logo_light: row.get(3)?,
                        logo_dark: row.get(4)?,
                        favicon: row.get(5)?,
                        revision: row.get(6)?,
                    })
                },
            )
            .optional()
        })
        .await
    }

    /// Name and colour of `scope`; `None` is UwULock's.
    pub async fn set_branding_text(&self, scope: &str, name: Option<String>, color: Option<String>) -> Result<()> {
        let scope = scope.to_string();
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO branding (scope, name, color, revision) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT (scope) DO UPDATE SET name = excluded.name, color = excluded.color, \
                 revision = excluded.revision",
                params![scope, name, color, clock::now()],
            )?;
            Ok(())
        })
        .await
    }

    /// One picture of `scope`, or none again.
    pub async fn set_branding_image(&self, scope: &str, image: Image, png: Option<Vec<u8>>) -> Result<()> {
        let scope = scope.to_string();
        let column = image.column();
        self.sqlite_write(move |tx| {
            tx.execute(
                &format!(
                    "INSERT INTO branding (scope, {column}, revision) VALUES (?1, ?2, ?3) \
                     ON CONFLICT (scope) DO UPDATE SET {column} = excluded.{column}, revision = excluded.revision"
                ),
                params![scope, png, clock::now()],
            )?;
            Ok(())
        })
        .await
    }

    /// Everything of `scope` back to UwULock's: for a send domain that goes.
    pub async fn delete_branding(&self, scope: &str) -> Result<()> {
        let scope = scope.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM branding WHERE scope = ?1", [scope])?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::tests::store;

    #[tokio::test]
    async fn branding_is_kept_per_scope() {
        let (store, _dir) = store();
        assert!(store.branding(SERVER).await.unwrap().is_none());
        store.set_branding_text(SERVER, Some("Post & Co".into()), Some("#0ea5e9".into())).await.unwrap();
        store.set_branding_image(SERVER, Image::LogoDark, Some(vec![1, 2, 3])).await.unwrap();
        store.set_branding_image("domain-1", Image::Favicon, Some(vec![4])).await.unwrap();
        let server = store.branding(SERVER).await.unwrap().unwrap();
        assert_eq!(server.name.as_deref(), Some("Post & Co"));
        assert_eq!(server.logo_dark.as_deref(), Some(&[1u8, 2, 3][..]));
        assert!(server.logo_light.is_none() && server.favicon.is_none());
        assert!(server.custom());

        // A picture taken away leaves name and colour; name and colour leave the pictures.
        store.set_branding_image(SERVER, Image::LogoDark, None).await.unwrap();
        store.set_branding_text(SERVER, None, Some("#0ea5e9".into())).await.unwrap();
        let server = store.branding(SERVER).await.unwrap().unwrap();
        assert!(server.logo_dark.is_none() && server.name.is_none());
        assert_eq!(server.color.as_deref(), Some("#0ea5e9"));

        let domain = store.branding("domain-1").await.unwrap().unwrap();
        assert_eq!(domain.favicon.as_deref(), Some(&[4u8][..]));
        assert!(domain.name.is_none());
        store.delete_branding("domain-1").await.unwrap();
        assert!(store.branding("domain-1").await.unwrap().is_none());
    }
}
