//! Filesystem path resolution and legacy migration.
//!
//! Paths follow [`directories::ProjectDirs`]: config directory for `slots.json`,
//! data directory for journal / HMAC key / locks, and the fixed
//! `~/.claude/.credentials.json` for what Claude Code itself reads.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use directories::{ProjectDirs, UserDirs};

fn home_dir() -> Option<PathBuf> {
    UserDirs::new().map(|u| u.home_dir().to_path_buf())
}

/// All filesystem paths used by the CLI.
#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub claude_credentials_json: PathBuf,
    pub slots_json: PathBuf,
    pub journal_dir: PathBuf,
    pub hmac_key: PathBuf,
    pub daemon_lock: PathBuf,
    pub state_lock: PathBuf,
}

/// Optional path overrides. Populated from env vars in production (via
/// [`PathOverrides::from_env`]) or injected directly by tests.
#[derive(Default, Debug, Clone)]
pub struct PathOverrides {
    pub config_dir: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    pub home_dir: Option<PathBuf>,
}

impl PathOverrides {
    /// Read overrides from environment variables. Each non-empty variable
    /// opts out of the corresponding platform default:
    ///
    /// - `CLAUDE_TOKEN_CONFIG_DIR` — overrides the config dir (slots.json lives here)
    /// - `CLAUDE_TOKEN_DATA_DIR` — overrides the data dir (journal, hmac key, locks, keystore)
    /// - `CLAUDE_TOKEN_HOME_DIR` — overrides `$HOME`, used only to locate
    ///   `.claude/.credentials.json`
    ///
    /// Intended for Docker/Kubernetes bind mounts, CI smoke tests, and
    /// sandboxed environments where platform defaults aren't writable.
    pub fn from_env() -> Self {
        fn var(name: &str) -> Option<PathBuf> {
            std::env::var_os(name).and_then(|v| {
                let s: PathBuf = v.into();
                if s.as_os_str().is_empty() {
                    None
                } else {
                    Some(s)
                }
            })
        }
        Self {
            config_dir: var("CLAUDE_TOKEN_CONFIG_DIR"),
            data_dir: var("CLAUDE_TOKEN_DATA_DIR"),
            home_dir: var("CLAUDE_TOKEN_HOME_DIR"),
        }
    }
}

/// Resolve paths using platform defaults, overridden by env variables when
/// present. See [`PathOverrides::from_env`] for the recognised variables.
pub fn resolve_paths() -> Result<Paths> {
    resolve_paths_with_overrides(&PathOverrides::from_env())
}

/// Resolve paths with optional overrides (used in tests).
pub fn resolve_paths_with_overrides(ov: &PathOverrides) -> Result<Paths> {
    let dirs = ProjectDirs::from("ai", "2lab", "claude-token-cli")
        .ok_or_else(|| anyhow!("could not resolve ProjectDirs for claude-token-cli"))?;

    let config_dir = ov
        .config_dir
        .clone()
        .unwrap_or_else(|| dirs.config_dir().to_path_buf());
    let data_dir = ov
        .data_dir
        .clone()
        .unwrap_or_else(|| dirs.data_dir().to_path_buf());

    let home = ov
        .home_dir
        .clone()
        .or_else(home_dir)
        .ok_or_else(|| anyhow!("could not resolve home directory"))?;

    let claude_credentials_json = home.join(".claude").join(".credentials.json");
    let slots_json = config_dir.join("slots.json");
    let journal_dir = data_dir.join("journal");
    let hmac_key = data_dir.join("hmac.key");
    let daemon_lock = data_dir.join("daemon.lock");
    let state_lock = data_dir.join(".state.lock");

    fs::create_dir_all(&config_dir)
        .with_context(|| format!("create config_dir {}", config_dir.display()))?;
    fs::create_dir_all(&data_dir)
        .with_context(|| format!("create data_dir {}", data_dir.display()))?;
    fs::create_dir_all(&journal_dir)
        .with_context(|| format!("create journal_dir {}", journal_dir.display()))?;

    Ok(Paths {
        config_dir,
        data_dir,
        claude_credentials_json,
        slots_json,
        journal_dir,
        hmac_key,
        daemon_lock,
        state_lock,
    })
}

/// Move a legacy `~/.claude/claude-token-cli.json` catalog to the new
/// `slots.json` location, leaving a `.moved` breadcrumb so the user can tell.
pub fn migrate_legacy(paths: &Paths) -> Result<()> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Ok(()),
    };
    let legacy = home.join(".claude").join("claude-token-cli.json");
    migrate_legacy_from(&legacy, paths)
}

/// Same as [`migrate_legacy`] but with an explicit source path for tests.
pub fn migrate_legacy_from(legacy: &Path, paths: &Paths) -> Result<()> {
    if !legacy.exists() {
        return Ok(());
    }
    if paths.slots_json.exists() {
        return Ok(());
    }
    if let Some(parent) = paths.slots_json.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(legacy, &paths.slots_json).with_context(|| {
        format!(
            "copy legacy slots {} -> {}",
            legacy.display(),
            paths.slots_json.display()
        )
    })?;
    let breadcrumb = legacy.with_extension("json.moved");
    fs::rename(legacy, &breadcrumb)
        .with_context(|| format!("rename legacy to breadcrumb {}", breadcrumb.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_paths_with_overrides_uses_overrides() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let cfg = tmp.path().join("cfg");
        let data = tmp.path().join("data");
        fs::create_dir_all(home.join(".claude")).unwrap();

        let ov = PathOverrides {
            config_dir: Some(cfg.clone()),
            data_dir: Some(data.clone()),
            home_dir: Some(home.clone()),
        };
        let p = resolve_paths_with_overrides(&ov).unwrap();

        assert_eq!(p.config_dir, cfg);
        assert_eq!(p.data_dir, data);
        assert_eq!(p.slots_json, cfg.join("slots.json"));
        assert_eq!(p.journal_dir, data.join("journal"));
        assert_eq!(
            p.claude_credentials_json,
            home.join(".claude").join(".credentials.json")
        );
        assert!(p.config_dir.exists());
        assert!(p.data_dir.exists());
        assert!(p.journal_dir.exists());
    }

    #[test]
    fn migrate_legacy_moves_file_and_leaves_breadcrumb() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".claude")).unwrap();
        let legacy = home.join(".claude").join("claude-token-cli.json");
        fs::write(&legacy, br#"{"version":1,"slots":[]}"#).unwrap();

        let ov = PathOverrides {
            config_dir: Some(tmp.path().join("cfg")),
            data_dir: Some(tmp.path().join("data")),
            home_dir: Some(home.clone()),
        };
        let paths = resolve_paths_with_overrides(&ov).unwrap();

        migrate_legacy_from(&legacy, &paths).unwrap();
        assert!(
            paths.slots_json.exists(),
            "slots.json should exist post-migration"
        );
        assert!(!legacy.exists(), "legacy should be renamed");
        assert!(home
            .join(".claude")
            .join("claude-token-cli.json.moved")
            .exists());
    }

    #[test]
    fn env_overrides_from_env() {
        // env is process-global. Guard all three variables together in one
        // test to avoid parallel-test races on the same env keys.
        struct Guard(Vec<(&'static str, Option<String>)>);
        impl Drop for Guard {
            fn drop(&mut self) {
                for (k, v) in &self.0 {
                    match v {
                        Some(val) => std::env::set_var(k, val),
                        None => std::env::remove_var(k),
                    }
                }
            }
        }
        let _g = Guard(vec![
            (
                "CLAUDE_TOKEN_CONFIG_DIR",
                std::env::var("CLAUDE_TOKEN_CONFIG_DIR").ok(),
            ),
            (
                "CLAUDE_TOKEN_DATA_DIR",
                std::env::var("CLAUDE_TOKEN_DATA_DIR").ok(),
            ),
            (
                "CLAUDE_TOKEN_HOME_DIR",
                std::env::var("CLAUDE_TOKEN_HOME_DIR").ok(),
            ),
        ]);

        // (1) Populated: every var propagates into the struct.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("cfg");
        let data = tmp.path().join("data");
        let home = tmp.path().join("home");
        std::env::set_var("CLAUDE_TOKEN_CONFIG_DIR", &cfg);
        std::env::set_var("CLAUDE_TOKEN_DATA_DIR", &data);
        std::env::set_var("CLAUDE_TOKEN_HOME_DIR", &home);
        let ov = PathOverrides::from_env();
        assert_eq!(ov.config_dir.as_deref(), Some(cfg.as_path()));
        assert_eq!(ov.data_dir.as_deref(), Some(data.as_path()));
        assert_eq!(ov.home_dir.as_deref(), Some(home.as_path()));

        // (2) Empty strings are treated as unset.
        std::env::set_var("CLAUDE_TOKEN_CONFIG_DIR", "");
        std::env::remove_var("CLAUDE_TOKEN_DATA_DIR");
        std::env::remove_var("CLAUDE_TOKEN_HOME_DIR");
        let ov = PathOverrides::from_env();
        assert!(ov.config_dir.is_none(), "empty string must be ignored");
        assert!(ov.data_dir.is_none());
        assert!(ov.home_dir.is_none());
    }

    #[test]
    fn migrate_legacy_skips_if_target_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".claude")).unwrap();
        let legacy = home.join(".claude").join("claude-token-cli.json");
        fs::write(&legacy, br#"{"legacy":true}"#).unwrap();

        let cfg = tmp.path().join("cfg");
        fs::create_dir_all(&cfg).unwrap();
        let existing = cfg.join("slots.json");
        fs::write(&existing, br#"{"version":1,"slots":[]}"#).unwrap();

        let ov = PathOverrides {
            config_dir: Some(cfg),
            data_dir: Some(tmp.path().join("data")),
            home_dir: Some(home.clone()),
        };
        let paths = resolve_paths_with_overrides(&ov).unwrap();
        migrate_legacy_from(&legacy, &paths).unwrap();

        // existing slots.json stays untouched; legacy stays in place
        let body = fs::read_to_string(&paths.slots_json).unwrap();
        assert!(body.contains("\"slots\""));
        assert!(
            legacy.exists(),
            "legacy must not be removed when target exists"
        );
    }
}
