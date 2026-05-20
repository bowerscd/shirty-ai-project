//! `yggdrasilctl validate` — offline config + rules sanity check.
//!
//! Parses the config file at `--config` (loading and validating its schema
//! via [`yggdrasil::config::ServerConfig::load`]) and then loads the rules
//! directory (either an explicit `--rules-dir <PATH>` override or
//! `[server].rules_dir` from the config) via [`yggdrasil::rules::load_dir`],
//! which exercises ratatoskr's per-rule + cross-rule uniqueness checks.
//!
//! Exits 0 on a clean pass; non-zero (with a diagnostic on stderr) on the
//! first error encountered. The command never contacts the running daemon
//! and never writes to disk — it is safe to run on a live host.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use serde::Serialize;

#[derive(Debug, Args)]
pub struct ValidateArgs {
    /// Override the rules directory. When omitted, uses
    /// `[server].rules_dir` from the loaded config (default
    /// `/etc/yggdrasil/conf.d`).
    #[arg(long)]
    rules_dir: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct ValidateReport {
    config_path: PathBuf,
    rules_dir: PathBuf,
    derived_mode: String,
    rule_count: u64,
}

pub async fn run(args: ValidateArgs, config_path: &Path, json: bool) -> anyhow::Result<ExitCode> {
    // ---- Phase 1: load + validate config ----
    let config = match yggdrasil::config::ServerConfig::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error ({}): {}", config_path.display(), e);
            return Ok(ExitCode::from(2));
        }
    };

    let mode = match config.derived_mode() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("config error ({}): {}", config_path.display(), e);
            return Ok(ExitCode::from(2));
        }
    };

    // ---- Phase 2: load + validate rules ----
    let rules_dir = args
        .rules_dir
        .clone()
        .unwrap_or_else(|| config.server.rules_dir.clone());

    let ruleset = match yggdrasil::rules::load_dir(&rules_dir) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("rules error ({}): {}", rules_dir.display(), e);
            return Ok(ExitCode::from(3));
        }
    };

    let report = ValidateReport {
        config_path: config_path.to_path_buf(),
        rules_dir: rules_dir.clone(),
        derived_mode: format!("{mode:?}").to_lowercase(),
        rule_count: ruleset.rules().len() as u64,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("config: {}  ok", report.config_path.display());
        println!("mode:   {}", report.derived_mode);
        println!(
            "rules:  {}  ok ({} rule{})",
            report.rules_dir.display(),
            report.rule_count,
            if report.rule_count == 1 { "" } else { "s" }
        );
    }

    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const GOOD_CONFIG: &str = r#"
[server]

[accept]
pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
listen = "0.0.0.0:51820"
"#;

    const BAD_CONFIG: &str = r#"
[server]
"#;

    const GOOD_RULE: &str = r#"
[[rules]]
name        = "echo-tcp"
listen      = "0.0.0.0:7000"
protocol    = "tcp"
target_port = 7001
"#;

    fn setup(config: &str, rule: Option<&str>) -> (TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let cfg_path = tmp.path().join("config.toml");
        let rules_dir = tmp.path().join("conf.d");
        fs::create_dir_all(&rules_dir).unwrap();

        // Inject rules_dir into the existing [server] table so the loaded
        // config points at the temp directory.
        let cfg_with_rules = config.replace(
            "[server]",
            &format!("[server]\nrules_dir = \"{}\"", rules_dir.display()),
        );
        fs::write(&cfg_path, cfg_with_rules).unwrap();

        if let Some(r) = rule {
            fs::write(rules_dir.join("rules.toml"), r).unwrap();
        }

        (tmp, cfg_path, rules_dir)
    }

    #[tokio::test]
    async fn validate_succeeds_for_good_config_and_rules() {
        let (_tmp, cfg, _rd) = setup(GOOD_CONFIG, Some(GOOD_RULE));
        let code = run(
            ValidateArgs { rules_dir: None },
            &cfg,
            true,
        )
        .await
        .unwrap();
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn validate_succeeds_with_empty_rules_dir() {
        let (_tmp, cfg, _rd) = setup(GOOD_CONFIG, None);
        let code = run(
            ValidateArgs { rules_dir: None },
            &cfg,
            false,
        )
        .await
        .unwrap();
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn validate_rejects_config_missing_dial_and_accept() {
        let (_tmp, cfg, _rd) = setup(BAD_CONFIG, None);
        let code = run(
            ValidateArgs { rules_dir: None },
            &cfg,
            false,
        )
        .await
        .unwrap();
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(2)));
    }

    #[tokio::test]
    async fn validate_rejects_invalid_rules() {
        let (_tmp, cfg, _rd) = setup(GOOD_CONFIG, Some("not-toml ::: ["));
        let code = run(
            ValidateArgs { rules_dir: None },
            &cfg,
            false,
        )
        .await
        .unwrap();
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(3)));
    }

    #[tokio::test]
    async fn validate_rules_dir_override_takes_precedence() {
        let (_tmp, cfg, _rd) = setup(GOOD_CONFIG, None);

        // Point at a nonexistent directory; this should fail (load_dir treats
        // a missing rules dir as a hard error).
        let bogus = std::path::PathBuf::from("/nonexistent/yggdrasilctl/test/dir");
        let code = run(
            ValidateArgs {
                rules_dir: Some(bogus),
            },
            &cfg,
            false,
        )
        .await
        .unwrap();
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(3)));
    }
}
