//! The web vault and the admin portal, as files: built from `web/` by `pnpm build` and embedded
//! into the binary by `build.rs`. Serving them is `uwulock-api`'s job; this crate only holds them,
//! so a change to the server's code does not embed them again, and theirs does not rebuild it.

/// One file of the build.
pub struct Asset {
    /// From the root of the build, with a leading slash: `/assets/index-1a2b3c.js`.
    pub path: &'static str,
    pub content_type: &'static str,
    pub bytes: &'static [u8],
    /// The same, compressed with brotli, if the build made that.
    pub brotli: Option<&'static [u8]>,
    /// The same, compressed with gzip, if the build made that.
    pub gzip: Option<&'static [u8]>,
}

include!(concat!(env!("OUT_DIR"), "/assets.rs"));

/// The file at `path`, if the build has it.
pub fn find(path: &str) -> Option<&'static Asset> {
    ASSETS.binary_search_by(|asset| asset.path.cmp(path)).ok().map(|index| &ASSETS[index])
}

/// Whether a web vault was built into this binary at all.
pub fn is_built() -> bool {
    find("/index.html").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_files_are_sorted_for_the_search() {
        assert!(ASSETS.windows(2).all(|pair| pair[0].path < pair[1].path));
        if is_built() {
            assert!(find("/index.html").is_some_and(|index| index.content_type.starts_with("text/html")));
        }
    }
}
