//! The icon databases compiled into the binary: the committed packs are the ones SHA256SUMS
//! names (scripts/icons/update.mjs made both), each can be read, and they know what they should.

use std::borrow::Cow;
use std::path::PathBuf;
use uwulock_api::icon_db::{ALL, Databases};

#[test]
fn the_bundled_packs_are_the_ones_made_and_can_be_read() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("icon-databases");
    let sums = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
    let mut packs = Vec::new();
    for id in ALL {
        let file = format!("{id}.pack");
        let bytes = std::fs::read(dir.join(&file)).unwrap();
        let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
        let hex: String = digest.as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
        assert!(sums.lines().any(|line| line == format!("{hex}  {file}")), "{file} is not the one in SHA256SUMS");
        packs.push(Cow::Owned(bytes));
    }
    let databases = Databases::parse(packs);
    assert_eq!(databases.all().len(), 3);
    let sources: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join("sources.json")).unwrap()).unwrap();
    for database in databases.all() {
        let (icons, ..) = database.counts();
        assert!(icons > 1000, "{}: {icons} icons", database.about.id);
        assert_eq!(
            sources[&database.about.id]["commit"],
            database.about.commit.as_str(),
            "made from the pinned commit"
        );
    }
    let all: Vec<String> = ALL.iter().map(|id| id.to_string()).collect();
    assert!(databases.for_host(&all, "github.com").is_some());
    assert!(databases.for_local(&all, "nextcloud.home.arpa").is_some());
}
