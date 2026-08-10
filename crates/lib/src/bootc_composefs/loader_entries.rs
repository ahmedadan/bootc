//! # Composefs backend for BLS entry kernel argument sources
//!
//! The ostree backend implements `set-options-for-source` by staging a new
//! deployment whose BLS entry is finalized at shutdown. On composefs hosts
//! the Type1 BLS entries live directly on the ESP, so we instead rewrite the
//! booted deployment's entry in place. If staged entries exist (a pending
//! upgrade), they are updated too so the change is not lost when the staged
//! entries are exchanged into place at shutdown.
//!
//! The `x-options-source-<name>` tracking keys round-trip through
//! [`BLSConfig::extra`], which preserves unknown BLS keys verbatim.

use anyhow::{Context, Result, anyhow};
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use linux_kernel_cmdline::utf8::{Cmdline, CmdlineOwned};
use rustix::fs::fsync;
use std::collections::BTreeMap;

use crate::bootc_composefs::status::ComposefsCmdline;
use crate::composefs_consts::{TYPE1_ENT_PATH, TYPE1_ENT_PATH_STAGED};
use crate::loader_entries::{OPTIONS_SOURCE_KEY_PREFIX, SourceName, compute_merged_options};
use crate::parsers::bls_config::{BLSConfig, BLSConfigType, parse_bls_config};
use crate::store::{BootedComposefs, Storage};

/// Read all Type1 `.conf` entries in `dir`, returning (filename, parsed config).
fn read_entries(dir: &Dir) -> Result<Vec<(String, BLSConfig)>> {
    let mut entries = Vec::new();
    for ent in dir.entries_utf8().context("Reading BLS entries dir")? {
        let ent = ent?;
        let name = ent.file_name()?;
        if !name.ends_with(".conf") {
            continue;
        }
        let content = dir
            .read_to_string(&name)
            .with_context(|| format!("Reading BLS entry {name}"))?;
        let cfg =
            parse_bls_config(&content).with_context(|| format!("Parsing BLS entry {name}"))?;
        entries.push((name, cfg));
    }
    Ok(entries)
}

/// Extract `x-options-source-*` keys from a parsed BLS config.
fn source_options_from_config(cfg: &BLSConfig) -> BTreeMap<String, CmdlineOwned> {
    let mut sources = BTreeMap::new();
    for (key, value) in &cfg.extra {
        if let Some(name) = key.strip_prefix(OPTIONS_SOURCE_KEY_PREFIX) {
            if !name.is_empty() && !value.is_empty() {
                sources.insert(name.to_string(), CmdlineOwned::from(value.clone()));
            }
        }
    }
    sources
}

/// Apply the source merge to one BLS config in place.
///
/// Returns `Ok(true)` if the config was modified, `Ok(false)` if the change
/// was a no-op for this entry.
fn apply_source_to_config(
    cfg: &mut BLSConfig,
    source: &SourceName,
    new_options: Option<&str>,
) -> Result<bool> {
    let current_options = match &cfg.cfg_type {
        BLSConfigType::NonEFI { options, .. } => options
            .as_ref()
            .map(|o| o.to_string())
            .unwrap_or_default(),
        BLSConfigType::EFI { .. } => anyhow::bail!(
            "Changing kernel arguments is not supported for UKI (Type2) boot entries"
        ),
        BLSConfigType::Unknown => anyhow::bail!("Unknown BLS config type"),
    };

    let source_options = source_options_from_config(cfg);
    let merged = compute_merged_options(&current_options, &source_options, source, new_options);
    let merged_str = merged.to_string();

    let is_options_unchanged = merged_str == current_options;
    let is_source_unchanged = match (source_options.get(&**source), new_options) {
        (Some(old), Some(new)) => &**old == new,
        (None, None) | (None, Some("")) => true,
        _ => false,
    };
    if is_options_unchanged && is_source_unchanged {
        return Ok(false);
    }

    match &mut cfg.cfg_type {
        BLSConfigType::NonEFI { options, .. } => {
            *options = Some(CmdlineOwned::from(merged_str));
        }
        // Unreachable: the EFI and Unknown cases bailed above.
        _ => unreachable!(),
    }

    let key = source.bls_key();
    match new_options.filter(|v| !v.is_empty()) {
        Some(v) => {
            cfg.extra.insert(key, v.to_string());
        }
        None => {
            cfg.extra.remove(&key);
        }
    }

    Ok(true)
}

/// Set the kernel arguments for a specific source on a composefs host.
///
/// The booted deployment's BLS entry (matched by composefs digest) is
/// rewritten in place with the merged `options` line and updated
/// `x-options-source-*` key. Staged entries, if present, receive the same
/// merge so a pending upgrade keeps the change. Unlike the ostree backend,
/// no deployment is staged: the change takes effect on the next boot
/// without any shutdown-time finalization.
#[context("Setting options for source '{source}' (composefs)")]
pub(crate) fn set_options_for_source_composefs(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    source: &str,
    new_options: Option<&str>,
) -> Result<()> {
    let source = SourceName::parse(source)?;
    let boot_dir = storage.require_boot_dir()?;
    let changed = apply_to_boot_dir(boot_dir, &booted_cfs.cmdline.digest, &source, new_options)?;
    if changed {
        tracing::info!("Updated BLS entries with kargs for source '{source}'");
    } else {
        tracing::info!("No changes needed for source '{source}'");
    }
    Ok(())
}

/// Apply the source merge to the entries under `boot_dir` (the directory
/// containing `loader/entries`): the booted entry, matched by composefs
/// digest, plus any staged entries. Returns whether anything was written.
fn apply_to_boot_dir(
    boot_dir: &Dir,
    booted_digest: &str,
    source: &SourceName,
    new_options: Option<&str>,
) -> Result<bool> {
    let entries_dir = boot_dir
        .open_dir(TYPE1_ENT_PATH)
        .with_context(|| format!("Opening {TYPE1_ENT_PATH}"))?;

    let mut changed = false;

    // Update the booted deployment's entry, matched by composefs digest.
    let mut booted_matched = false;
    for (file_name, mut cfg) in read_entries(&entries_dir)? {
        let is_booted = match &cfg.cfg_type {
            BLSConfigType::NonEFI {
                options: Some(opts),
                ..
            } => ComposefsCmdline::find_in_cmdline(&Cmdline::from(opts))
                .is_some_and(|c| &*c.digest == booted_digest),
            _ => false,
        };
        if !is_booted {
            continue;
        }
        booted_matched = true;
        if apply_source_to_config(&mut cfg, source, new_options)? {
            entries_dir
                .atomic_write(&file_name, cfg.to_string())
                .with_context(|| format!("Writing {file_name}"))?;
            changed = true;
        }
        break;
    }
    if !booted_matched {
        return Err(anyhow!("No BLS entry found for booted deployment"));
    }

    if changed {
        let fd = entries_dir
            .reopen_as_ownedfd()
            .context("Reopening entries dir")?;
        fsync(fd).context("fsync entries dir")?;
    }

    // Propagate to staged entries so a pending upgrade keeps the change
    // when loader/entries.staged is exchanged into place at shutdown.
    if let Some(staged_dir) = boot_dir.open_dir_optional(TYPE1_ENT_PATH_STAGED)? {
        let mut staged_changed = false;
        for (file_name, mut cfg) in read_entries(&staged_dir)? {
            if apply_source_to_config(&mut cfg, source, new_options)? {
                staged_dir
                    .atomic_write(&file_name, cfg.to_string())
                    .with_context(|| format!("Writing staged {file_name}"))?;
                staged_changed = true;
            }
        }
        if staged_changed {
            let fd = staged_dir
                .reopen_as_ownedfd()
                .context("Reopening staged entries dir")?;
            fsync(fd).context("fsync staged entries dir")?;
            changed = true;
        }
    }

    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::bls_config::parse_bls_config;

    const ENTRY: &str = "\
title Dakota (bluefin)
version 20260808
linux /boot/1234/vmlinuz
initrd /boot/1234/initrd
options root=LABEL=root rw composefs=abcd1234 rhgb quiet
";

    #[test]
    fn test_apply_source_add_update_remove() {
        let mut cfg = parse_bls_config(ENTRY).unwrap();
        let source = SourceName::parse("admin").unwrap();

        // Add
        let changed = apply_source_to_config(&mut cfg, &source, Some("amdgpu.runpm=0")).unwrap();
        assert!(changed);
        let text = cfg.to_string();
        assert!(text.contains("options root=LABEL=root rw composefs=abcd1234 rhgb quiet amdgpu.runpm=0"));
        assert!(text.contains("x-options-source-admin amdgpu.runpm=0"));

        // Idempotent
        let changed = apply_source_to_config(&mut cfg, &source, Some("amdgpu.runpm=0")).unwrap();
        assert!(!changed);

        // Update replaces only this source's args
        let changed = apply_source_to_config(&mut cfg, &source, Some("amdgpu.runpm=1")).unwrap();
        assert!(changed);
        let text = cfg.to_string();
        assert!(text.contains("amdgpu.runpm=1"));
        assert!(!text.contains("amdgpu.runpm=0"));

        // Remove drops the args and the tracking key
        let changed = apply_source_to_config(&mut cfg, &source, None).unwrap();
        assert!(changed);
        let text = cfg.to_string();
        assert!(!text.contains("amdgpu.runpm"));
        assert!(!text.contains("x-options-source-admin"));
        assert!(text.contains("options root=LABEL=root rw composefs=abcd1234 rhgb quiet"));
    }

    const BOOTED_DIGEST: &str = "aaaa1111";
    const ROLLBACK_DIGEST: &str = "bbbb2222";
    const STAGED_DIGEST: &str = "cccc3333";

    fn entry_text(digest: &str) -> String {
        format!(
            "title Dakota (bluefin)\n\
             version 20260808\n\
             linux /boot/{digest}/vmlinuz\n\
             initrd /boot/{digest}/initrd\n\
             options root=LABEL=root rw composefs={digest} rhgb quiet\n"
        )
    }

    fn fixture_boot_dir() -> cap_std_ext::cap_tempfile::TempDir {
        let td =
            cap_std_ext::cap_tempfile::TempDir::new(cap_std_ext::cap_std::ambient_authority())
                .unwrap();
        td.create_dir_all(TYPE1_ENT_PATH).unwrap();
        let entries = td.open_dir(TYPE1_ENT_PATH).unwrap();
        entries
            .atomic_write("bootc_dakota-20260808-1.conf", entry_text(BOOTED_DIGEST))
            .unwrap();
        entries
            .atomic_write("bootc_dakota-20260807-0.conf", entry_text(ROLLBACK_DIGEST))
            .unwrap();
        td
    }

    #[test]
    fn test_apply_to_boot_dir_targets_booted_entry_only() {
        let td = fixture_boot_dir();
        let source = SourceName::parse("admin").unwrap();

        let changed =
            apply_to_boot_dir(&td, BOOTED_DIGEST, &source, Some("amdgpu.runpm=0")).unwrap();
        assert!(changed);

        let entries = td.open_dir(TYPE1_ENT_PATH).unwrap();
        let booted = entries
            .read_to_string("bootc_dakota-20260808-1.conf")
            .unwrap();
        assert!(booted.contains("amdgpu.runpm=0"));
        assert!(booted.contains("x-options-source-admin amdgpu.runpm=0"));

        // The rollback entry must be byte-for-byte untouched.
        let rollback = entries
            .read_to_string("bootc_dakota-20260807-0.conf")
            .unwrap();
        assert_eq!(rollback, entry_text(ROLLBACK_DIGEST));
    }

    #[test]
    fn test_apply_to_boot_dir_unknown_digest_fails() {
        let td = fixture_boot_dir();
        let source = SourceName::parse("admin").unwrap();
        assert!(apply_to_boot_dir(&td, "ffff9999", &source, Some("a=b")).is_err());
    }

    #[test]
    fn test_apply_to_boot_dir_propagates_to_staged() {
        let td = fixture_boot_dir();
        td.create_dir_all(TYPE1_ENT_PATH_STAGED).unwrap();
        let staged = td.open_dir(TYPE1_ENT_PATH_STAGED).unwrap();
        staged
            .atomic_write("bootc_dakota-20260809-1.conf", entry_text(STAGED_DIGEST))
            .unwrap();

        let source = SourceName::parse("admin").unwrap();
        let changed =
            apply_to_boot_dir(&td, BOOTED_DIGEST, &source, Some("amdgpu.runpm=0")).unwrap();
        assert!(changed);

        // The staged entry (a pending upgrade with a different digest) must
        // receive the same merge, or the change is lost at the shutdown-time
        // entries exchange.
        let staged_text = staged
            .read_to_string("bootc_dakota-20260809-1.conf")
            .unwrap();
        assert!(staged_text.contains("amdgpu.runpm=0"));
        assert!(staged_text.contains("x-options-source-admin amdgpu.runpm=0"));

        // Removal propagates too.
        let changed = apply_to_boot_dir(&td, BOOTED_DIGEST, &source, None).unwrap();
        assert!(changed);
        let staged_text = staged
            .read_to_string("bootc_dakota-20260809-1.conf")
            .unwrap();
        assert!(!staged_text.contains("amdgpu.runpm"));
        assert!(!staged_text.contains("x-options-source-admin"));
    }

    #[test]
    fn test_apply_to_boot_dir_idempotent_leaves_files_alone() {
        let td = fixture_boot_dir();
        let source = SourceName::parse("admin").unwrap();

        let changed =
            apply_to_boot_dir(&td, BOOTED_DIGEST, &source, Some("amdgpu.runpm=0")).unwrap();
        assert!(changed);
        let entries = td.open_dir(TYPE1_ENT_PATH).unwrap();
        let after_first = entries
            .read_to_string("bootc_dakota-20260808-1.conf")
            .unwrap();

        let changed =
            apply_to_boot_dir(&td, BOOTED_DIGEST, &source, Some("amdgpu.runpm=0")).unwrap();
        assert!(!changed);
        let after_second = entries
            .read_to_string("bootc_dakota-20260808-1.conf")
            .unwrap();
        assert_eq!(after_first, after_second);
    }

    #[test]
    fn test_apply_source_uki_entry_fails() {
        let uki = "\
title Dakota
version 20260808
uki /EFI/Linux/foo.efi
";
        let mut cfg = parse_bls_config(uki).unwrap();
        let source = SourceName::parse("admin").unwrap();
        assert!(apply_source_to_config(&mut cfg, &source, Some("a=b")).is_err());
    }
}
