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
use linux_kernel_cmdline::utf8::CmdlineOwned;
use rustix::fs::fsync;
use std::collections::BTreeMap;

use crate::bootc_composefs::status::StagedDeployment;
use crate::composefs_consts::{
    COMPOSEFS_STAGED_DEPLOYMENT_FNAME, COMPOSEFS_TRANSIENT_STATE_DIR_RUN_RELATIVE, TYPE1_ENT_PATH,
    TYPE1_ENT_PATH_STAGED, TYPE1_ENTRY_CONF_PREFIX,
};
use crate::loader_entries::{OPTIONS_SOURCE_KEY_PREFIX, SourceName, compute_merged_options};
use crate::parsers::bls_config::{BLSConfig, BLSConfigType, parse_bls_config};
use crate::store::{BootedComposefs, Storage};

/// Read bootc-owned Type 1 entries in `dir`, returning (filename, parsed config).
///
/// Current entries use the `bootc_` filename prefix. For compatibility with
/// older names, a valid entry carrying a bootc composefs digest is accepted too.
/// Unrelated BLS entries on a shared ESP are ignored, including malformed ones.
fn read_entries(dir: &Dir) -> Result<Vec<(String, BLSConfig)>> {
    let mut entries = Vec::new();
    for ent in dir.entries_utf8().context("Reading BLS entries dir")? {
        let ent = ent?;
        let name = ent.file_name()?;
        if !name.ends_with(".conf") {
            continue;
        }

        let is_current_bootc_name = name.starts_with(TYPE1_ENTRY_CONF_PREFIX);
        let content = dir
            .read_to_string(&name)
            .with_context(|| format!("Reading BLS entry {name}"))?;
        let cfg = match parse_bls_config(&content) {
            Ok(cfg) => cfg,
            Err(err) if !is_current_bootc_name => {
                tracing::debug!(entry = name, %err, "Ignoring unrelated malformed BLS entry");
                continue;
            }
            Err(err) => return Err(err).with_context(|| format!("Parsing BLS entry {name}")),
        };

        if is_current_bootc_name || cfg.get_verity().is_ok() {
            entries.push((name, cfg));
        }
    }
    Ok(entries)
}

/// Read the target digest for a pending composefs deployment.
fn read_staged_digest(storage: &Storage) -> Result<Option<String>> {
    let Some(transient_dir) = storage
        .run_dir()
        .open_dir_optional(COMPOSEFS_TRANSIENT_STATE_DIR_RUN_RELATIVE)
        .context("Opening transient composefs state")?
    else {
        return Ok(None);
    };
    let Some(data) = transient_dir
        .read_to_string_optional(COMPOSEFS_STAGED_DEPLOYMENT_FNAME)
        .context("Reading staged composefs deployment metadata")?
    else {
        return Ok(None);
    };
    let staged: StagedDeployment =
        serde_json::from_str(&data).context("Parsing staged composefs deployment metadata")?;
    Ok(Some(staged.depl_id))
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
        BLSConfigType::NonEFI { options, .. } => {
            options.as_ref().map(|o| o.to_string()).unwrap_or_default()
        }
        BLSConfigType::EFI { .. } => {
            anyhow::bail!("Changing kernel arguments is not supported for UKI (Type2) boot entries")
        }
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
/// `x-options-source-*` key. If an upgrade is pending, its target entry is
/// updated too; the future rollback entry remains unchanged. Unlike the ostree
/// backend, no deployment is staged by this command: the change takes effect on
/// the next boot without any shutdown-time finalization.
#[context("Setting options for source '{source}' (composefs)")]
pub(crate) fn set_options_for_source_composefs(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    source: &str,
    new_options: Option<&str>,
) -> Result<()> {
    let source = SourceName::parse(source)?;
    let staged_digest = read_staged_digest(storage)?;
    let boot_dir = storage.require_boot_dir()?;
    let changed = apply_to_boot_dir(
        boot_dir,
        &booted_cfs.cmdline.digest,
        staged_digest.as_deref(),
        &source,
        new_options,
    )?;
    if changed {
        tracing::info!("Updated BLS entries with kargs for source '{source}'");
    } else {
        tracing::info!("No changes needed for source '{source}'");
    }
    Ok(())
}

struct PlannedEntryUpdate {
    file_name: String,
    content: String,
}

/// Compute an update for the entry matching `target_digest` without writing it.
fn plan_entry_update(
    dir: &Dir,
    target_digest: &str,
    source: &SourceName,
    new_options: Option<&str>,
    deployment_kind: &str,
) -> Result<Option<PlannedEntryUpdate>> {
    let mut matched = None;
    for (file_name, cfg) in read_entries(dir)? {
        if cfg.get_verity().is_ok_and(|digest| digest == target_digest) {
            if matched.is_some() {
                anyhow::bail!("Multiple BLS entries found for {deployment_kind} deployment");
            }
            matched = Some((file_name, cfg));
        }
    }

    let Some((file_name, mut cfg)) = matched else {
        return Err(anyhow!(
            "No BLS entry found for {deployment_kind} deployment"
        ));
    };

    if !apply_source_to_config(&mut cfg, source, new_options)? {
        return Ok(None);
    }

    Ok(Some(PlannedEntryUpdate {
        file_name,
        content: cfg.to_string(),
    }))
}

fn write_planned_update(dir: &Dir, update: PlannedEntryUpdate, staged: bool) -> Result<()> {
    dir.atomic_write(&update.file_name, update.content)
        .with_context(|| {
            if staged {
                format!("Writing staged {}", update.file_name)
            } else {
                format!("Writing {}", update.file_name)
            }
        })?;
    let fd = dir.reopen_as_ownedfd().context("Reopening entries dir")?;
    fsync(fd).context("fsync entries dir")
}

/// Apply the source merge to the booted entry and pending deployment target.
///
/// All entries are parsed and all changes are computed before the first write,
/// so unsupported or malformed staged entries cannot leave a partial update.
fn apply_to_boot_dir(
    boot_dir: &Dir,
    booted_digest: &str,
    staged_digest: Option<&str>,
    source: &SourceName,
    new_options: Option<&str>,
) -> Result<bool> {
    let entries_dir = boot_dir
        .open_dir(TYPE1_ENT_PATH)
        .with_context(|| format!("Opening {TYPE1_ENT_PATH}"))?;
    let staged_dir = boot_dir.open_dir_optional(TYPE1_ENT_PATH_STAGED)?;

    let booted_update =
        plan_entry_update(&entries_dir, booted_digest, source, new_options, "booted")?;
    let staged_update = match (staged_dir.as_ref(), staged_digest) {
        (Some(dir), Some(digest)) => plan_entry_update(dir, digest, source, new_options, "staged")?,
        (None, None) => None,
        (Some(_), None) => {
            // The entries directory is created before staged metadata is
            // committed, and may remain after an interrupted upgrade. Without
            // metadata there is no pending deployment to preserve.
            tracing::debug!("Ignoring staged BLS entries without staged deployment metadata");
            None
        }
        (None, Some(_)) => {
            anyhow::bail!("Found staged deployment metadata without staged BLS entries")
        }
    };

    let mut changed = false;
    if let Some(update) = booted_update {
        write_planned_update(&entries_dir, update, false)?;
        changed = true;
    }
    if let (Some(dir), Some(update)) = (staged_dir.as_ref(), staged_update) {
        write_planned_update(dir, update, true)?;
        changed = true;
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
        assert!(
            text.contains(
                "options root=LABEL=root rw composefs=abcd1234 rhgb quiet amdgpu.runpm=0"
            )
        );
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

    fn uki_entry_text(digest: &str) -> String {
        format!(
            "title Dakota (bluefin)\n\
             version 20260808\n\
             uki /EFI/Linux/bootc_composefs-{digest}.efi\n"
        )
    }

    fn fixture_boot_dir() -> cap_std_ext::cap_tempfile::TempDir {
        let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std_ext::cap_std::ambient_authority())
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
    fn test_read_entries_ignores_foreign_and_accepts_legacy_names() {
        let td = fixture_boot_dir();
        let entries = td.open_dir(TYPE1_ENT_PATH).unwrap();
        entries
            .atomic_write("foreign.conf", "not a valid BLS entry\n")
            .unwrap();
        entries
            .atomic_write("legacy-name.conf", entry_text(STAGED_DIGEST))
            .unwrap();

        let found = read_entries(&entries).unwrap();
        assert_eq!(found.len(), 3);
        assert!(found.iter().any(|(name, _)| name == "legacy-name.conf"));
        assert!(!found.iter().any(|(name, _)| name == "foreign.conf"));
    }

    #[test]
    fn test_apply_to_boot_dir_targets_booted_entry_only() {
        let td = fixture_boot_dir();
        let source = SourceName::parse("admin").unwrap();

        let changed =
            apply_to_boot_dir(&td, BOOTED_DIGEST, None, &source, Some("amdgpu.runpm=0")).unwrap();
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
        assert!(apply_to_boot_dir(&td, "ffff9999", None, &source, Some("a=b")).is_err());
    }

    #[test]
    fn test_apply_to_boot_dir_propagates_only_to_staged_target() {
        let td = fixture_boot_dir();
        td.create_dir_all(TYPE1_ENT_PATH_STAGED).unwrap();
        let staged = td.open_dir(TYPE1_ENT_PATH_STAGED).unwrap();
        staged
            .atomic_write("bootc_dakota-20260809-1.conf", entry_text(STAGED_DIGEST))
            .unwrap();
        staged
            .atomic_write("bootc_dakota-20260808-0.conf", entry_text(BOOTED_DIGEST))
            .unwrap();

        let source = SourceName::parse("admin").unwrap();
        let changed = apply_to_boot_dir(
            &td,
            BOOTED_DIGEST,
            Some(STAGED_DIGEST),
            &source,
            Some("amdgpu.runpm=0"),
        )
        .unwrap();
        assert!(changed);

        let staged_text = staged
            .read_to_string("bootc_dakota-20260809-1.conf")
            .unwrap();
        assert!(staged_text.contains("amdgpu.runpm=0"));
        assert!(staged_text.contains("x-options-source-admin amdgpu.runpm=0"));

        // The secondary entry becomes rollback after finalization and must keep
        // the kargs associated with that deployment.
        let future_rollback = staged
            .read_to_string("bootc_dakota-20260808-0.conf")
            .unwrap();
        assert_eq!(future_rollback, entry_text(BOOTED_DIGEST));

        // Removal propagates to the pending target too.
        let changed =
            apply_to_boot_dir(&td, BOOTED_DIGEST, Some(STAGED_DIGEST), &source, None).unwrap();
        assert!(changed);
        let staged_text = staged
            .read_to_string("bootc_dakota-20260809-1.conf")
            .unwrap();
        assert!(!staged_text.contains("amdgpu.runpm"));
        assert!(!staged_text.contains("x-options-source-admin"));
    }

    #[test]
    fn test_stale_staged_entries_without_metadata_are_ignored() {
        let td = fixture_boot_dir();
        td.create_dir_all(TYPE1_ENT_PATH_STAGED).unwrap();
        let staged = td.open_dir(TYPE1_ENT_PATH_STAGED).unwrap();
        staged
            .atomic_write("bootc_dakota-20260809-1.conf", entry_text(STAGED_DIGEST))
            .unwrap();

        let source = SourceName::parse("admin").unwrap();
        let changed =
            apply_to_boot_dir(&td, BOOTED_DIGEST, None, &source, Some("amdgpu.runpm=0")).unwrap();
        assert!(changed);

        let stale = staged
            .read_to_string("bootc_dakota-20260809-1.conf")
            .unwrap();
        assert_eq!(stale, entry_text(STAGED_DIGEST));
    }

    #[test]
    fn test_staged_validation_happens_before_booted_write() {
        let td = fixture_boot_dir();
        td.create_dir_all(TYPE1_ENT_PATH_STAGED).unwrap();
        let staged = td.open_dir(TYPE1_ENT_PATH_STAGED).unwrap();
        staged
            .atomic_write(
                "bootc_dakota-20260809-1.conf",
                uki_entry_text(STAGED_DIGEST),
            )
            .unwrap();
        let entries = td.open_dir(TYPE1_ENT_PATH).unwrap();
        let before = entries
            .read_to_string("bootc_dakota-20260808-1.conf")
            .unwrap();

        let source = SourceName::parse("admin").unwrap();
        let err = apply_to_boot_dir(
            &td,
            BOOTED_DIGEST,
            Some(STAGED_DIGEST),
            &source,
            Some("amdgpu.runpm=0"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not supported for UKI"));

        let after = entries
            .read_to_string("bootc_dakota-20260808-1.conf")
            .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn test_apply_to_boot_dir_idempotent_leaves_files_alone() {
        let td = fixture_boot_dir();
        let source = SourceName::parse("admin").unwrap();

        let changed =
            apply_to_boot_dir(&td, BOOTED_DIGEST, None, &source, Some("amdgpu.runpm=0")).unwrap();
        assert!(changed);
        let entries = td.open_dir(TYPE1_ENT_PATH).unwrap();
        let after_first = entries
            .read_to_string("bootc_dakota-20260808-1.conf")
            .unwrap();

        let changed =
            apply_to_boot_dir(&td, BOOTED_DIGEST, None, &source, Some("amdgpu.runpm=0")).unwrap();
        assert!(!changed);
        let after_second = entries
            .read_to_string("bootc_dakota-20260808-1.conf")
            .unwrap();
        assert_eq!(after_first, after_second);
    }

    #[test]
    fn test_apply_to_boot_dir_uki_entry_fails_cleanly() {
        let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std_ext::cap_std::ambient_authority())
            .unwrap();
        td.create_dir_all(TYPE1_ENT_PATH).unwrap();
        let entries = td.open_dir(TYPE1_ENT_PATH).unwrap();
        entries
            .atomic_write(
                "bootc_dakota-20260808-1.conf",
                uki_entry_text(BOOTED_DIGEST),
            )
            .unwrap();

        let source = SourceName::parse("admin").unwrap();
        let err = apply_to_boot_dir(&td, BOOTED_DIGEST, None, &source, Some("a=b")).unwrap_err();
        assert!(err.to_string().contains("not supported for UKI"));
    }
}
