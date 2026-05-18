//! Rules subsystem — directory loading and (later) hot reloading.
//!
//! This module bridges the on-disk `/etc/yggdrasil/conf.d/*.toml` layout to
//! the schema types in [`ratatoskr::rule`]. The file-by-file parsing,
//! per-rule validation, and cross-file uniqueness checks all live in the
//! proto crate; this module just walks the filesystem and produces a single
//! aggregated [`RuleSet`].
//!
//! The hot-reload watcher lives in [`watcher`]; consumers typically interact
//! with this subsystem through [`RuleWatcher`].

mod watcher;

#[allow(unused_imports)] // re-exports used by Phase 4/5 proxy modules
pub use ratatoskr::rule::{
    RuleDiff, Protocol, ProxyProto, Rule, RuleChange, RuleFile, RuleSet,
    DEFAULT_UDP_IDLE_TIMEOUT,
};
#[allow(unused_imports)]
pub use watcher::{RuleUpdate, RuleWatcher, ReloadTrigger};

use std::path::{Path, PathBuf};

use ratatoskr::error::Result as ProtoResult;
use ratatoskr::Error;

/// Walk `dir` for `*.toml` files (non-recursive, sorted by filename), parse and
/// validate each, then aggregate into a single [`RuleSet`].
///
/// A missing directory is a hard error — operators should provision an empty
/// directory rather than leave it absent. An empty directory is OK and
/// produces an empty [`RuleSet`].
#[allow(dead_code)] // wired into run() in Phase 4
pub fn load_dir(dir: &Path) -> ProtoResult<RuleSet> {
    let files = read_toml_files(dir)?;
    let parsed: Vec<RuleFile> = files
        .iter()
        .map(|(path, contents)| RuleFile::from_toml(path.clone(), contents))
        .collect::<ProtoResult<_>>()?;
    RuleSet::from_files(parsed)
}

/// List `*.toml` files in `dir` (non-recursive), return `(path, contents)`
/// pairs sorted by path. Exposed for the future hot-reload watcher to share
/// file-listing logic.
#[allow(dead_code)] // used by Phase 3.2 watcher
pub fn read_toml_files(dir: &Path) -> ProtoResult<Vec<(PathBuf, String)>> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|source| Error::ReadFile {
            path: dir.to_path_buf(),
            source,
        })?
        .filter_map(|res| res.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.eq_ignore_ascii_case("toml"))
        })
        .collect();
    entries.sort();

    let mut out = Vec::with_capacity(entries.len());
    for path in entries {
        let contents = std::fs::read_to_string(&path).map_err(|source| Error::ReadFile {
            path: path.clone(),
            source,
        })?;
        out.push((path, contents));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("create tempdir")
    }

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).expect("write fixture");
    }

    #[test]
    fn empty_directory_yields_empty_set() {
        let d = tmpdir();
        let set = load_dir(d.path()).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn missing_directory_is_an_error() {
        let path = Path::new("/nonexistent/rules/dir/x");
        let err = load_dir(path).err();
        assert!(matches!(err, Some(Error::ReadFile { .. })));
    }

    #[test]
    fn loads_and_aggregates_multiple_files() {
        let d = tmpdir();
        write(
            d.path(),
            "alpha.toml",
            r#"
            [[rule]]
            name = "a"
            listen = "0.0.0.0:1111"
            protocol = "tcp"
            upstream_port = 1
            "#,
        );
        write(
            d.path(),
            "bravo.toml",
            r#"
            [[rule]]
            name = "b"
            listen = "0.0.0.0:2222"
            protocol = "udp"
            upstream_port = 2
            idle_timeout = "10s"
            "#,
        );
        let set = load_dir(d.path()).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.find("a").is_some());
        assert!(set.find("b").is_some());
    }

    #[test]
    fn non_toml_files_are_ignored() {
        let d = tmpdir();
        write(d.path(), "README.md", "not a rule");
        write(d.path(), "valid.toml", "");
        // No rules in the empty toml file, no panic on README.
        let set = load_dir(d.path()).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn parse_error_surfaces_with_path() {
        let d = tmpdir();
        write(d.path(), "broken.toml", "[[rule\nname=oops");
        let err = load_dir(d.path()).err();
        match err {
            Some(Error::TomlParse { path, .. }) => {
                assert!(path.ends_with("broken.toml"));
            }
            other => panic!("expected TomlParse, got {other:?}"),
        }
    }

    #[test]
    fn cross_file_duplicate_name_rejected() {
        let d = tmpdir();
        write(
            d.path(),
            "a.toml",
            r#"[[rule]]
            name="dup"
            listen="0.0.0.0:1"
            protocol="tcp"
            upstream_port=1
            "#,
        );
        write(
            d.path(),
            "b.toml",
            r#"[[rule]]
            name="dup"
            listen="0.0.0.0:2"
            protocol="tcp"
            upstream_port=2
            "#,
        );
        let err = load_dir(d.path()).err();
        assert!(matches!(err, Some(Error::InvalidRule(s)) if s.contains("duplicate")));
    }
}
