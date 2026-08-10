# number: 42
# tmt:
#   summary: Test bootc loader-entries set-options-for-source
#   duration: 30m
#
# This test verifies the source-tracked kernel argument management via
# bootc loader-entries set-options-for-source. It covers:
# 1. Input validation (invalid/empty source names)
# 2. Adding source-tracked kargs and verifying they appear in /proc/cmdline
# 3. Kargs and x-options-source-* BLS keys surviving the staging roundtrip
# 4. Source replacement semantics (old kargs removed, new ones added)
# 5. Multiple sources coexisting independently
# 6. Source removal (--source without --options clears all owned kargs)
# 7. Idempotent operation (no changes when kargs already match)
# 8. Existing system kargs (root=, ostree=, etc.) preserved through changes
# 9. --options "" (empty string) clears kargs without removing the source
# 10. Staged deployment interaction (bootc switch + set-options-for-source
#     preserves the pending image switch)
# 11. On UKI hosts the command fails cleanly (the cmdline is embedded in
#     the signed UKI, so there is no options line to edit)
#
# Backend differences: on ostree the change is applied by staging a
# deployment finalized at shutdown, so `bootc status` shows a staged
# deployment and nothing is on disk until reboot. On composefs the booted
# entry (and any staged entries) are rewritten in place immediately, and
# no deployment is staged. The assert_options_recorded and
# assert_options_cleared helpers cover both.
#
# The ostree backend requires ostree with bootconfig-extra support
# (>= 2026.1); the composefs backend has no such requirement.
# See: https://github.com/ostreedev/ostree/pull/3570
# See: https://github.com/bootc-dev/bootc/issues/899
use std assert
use tap.nu

def is_composefs [] {
    open /proc/cmdline | str contains "composefs="
}

if not (is_composefs) {
    let is_bad_version = ostree --version | lines | any {|l| $l | str contains "2026.2" }

    if $is_bad_version {
        print "Found Ostree v2026.2, skipping test"
        exit 0
    }
}

def parse_cmdline [] {
    open /proc/cmdline | str trim | split row " "
}

# Path of the booted deployment's BLS entry.
# ostree: the booted deployment always has the highest version number, so
# we pick the last entry when sorted by filename (ostree-N.conf).
# composefs: entries are named bootc_*.conf and the booted one is matched
# by the composefs=<digest> parameter from our own /proc/cmdline.
def booted_bls_entry [] {
    if (is_composefs) {
        let digest_param = parse_cmdline | where {|k| $k | str starts-with "composefs=" } | first
        let entries = glob /boot/loader/entries/*.conf
        let matching = $entries | where {|e| open $e | str contains $digest_param }
        if ($matching | length) == 0 {
            error make { msg: "No BLS entry matching booted composefs digest" }
        }
        $matching | first
    } else {
        let entries = glob /boot/loader/entries/ostree-*.conf | sort
        if ($entries | length) == 0 {
            error make { msg: "No BLS entries found" }
        }
        $entries | last
    }
}

# Read x-options-source-* keys from the booted BLS entry.
def read_bls_source_keys [] {
    open (booted_bls_entry) | lines | where { |line| $line starts-with "x-options-source-" }
}

# A UKI host has no Type1 entry with an editable options line: either there
# are no .conf entries at all (Type2 autodiscovery), or the entries use the
# `uki`/`efi` key instead of `linux`.
def uki_host [] {
    let entries = glob /boot/loader/entries/*.conf
    if ($entries | length) == 0 {
        return true
    }
    $entries | all {|e|
        open $e | lines | any {|l| ($l | str starts-with "uki ") or ($l | str starts-with "efi ") }
    }
}

# Assert that a karg change has been recorded, whichever backend.
# ostree: the change lives in a staged deployment (nothing on disk yet).
# composefs: the booted entry has been rewritten in place.
def assert_options_recorded [karg: string] {
    if (is_composefs) {
        let entry = open (booted_bls_entry)
        assert ($entry | str contains $karg) $"booted entry should contain ($karg)"
    } else {
        let st = bootc status --json | from json
        assert ($st.status.staged != null) "deployment should be staged"
    }
}

# Assert that a karg has been cleared from the pending state.
def assert_options_cleared [karg: string] {
    if (is_composefs) {
        let entry = open (booted_bls_entry)
        assert (not ($entry | str contains $karg)) $"booted entry should no longer contain ($karg)"
    } else {
        let st = bootc status --json | from json
        assert ($st.status.staged != null) "clearing options should still stage a deployment"
    }
}

# Save the current system kargs (root=, ostree=, rw, etc.) for later comparison
def save_system_kargs [] {
    let cmdline = parse_cmdline
    # Filter to well-known system kargs that must never be lost
    # Note: ostree= is excluded because its value changes between deployments
    # (boot version counter, bootcsum). It's managed by ostree's
    # install_deployment_kernel() and always regenerated during finalization.
    let system_kargs = $cmdline | where { |k|
        (($k starts-with "root=") or ($k == "rw") or ($k starts-with "console="))
    }
    $system_kargs | to json | save -f /var/bootc-test-system-kargs.json
}

def load_system_kargs [] {
    open /var/bootc-test-system-kargs.json
}

def first_boot [] {
    tap begin "loader-entries set-options-for-source"

    # -- UKI hosts: the command must fail cleanly, nothing else to test --
    if (uki_host) {
        let r = do -i { bootc loader-entries set-options-for-source --source admin --options "testuki=1" } | complete
        assert ($r.exit_code != 0) "set-options-for-source should fail on UKI entries"
        assert ($r.stderr | str contains "not supported") "failure should name UKI entries as unsupported"
        print "ok: UKI entries rejected cleanly"
        tap ok
        return
    }

    # Save system kargs for later verification
    save_system_kargs

    # -- Input validation --

    # Invalid source name (spaces)
    let r = do -i { bootc loader-entries set-options-for-source --source "bad name" --options "foo=bar" } | complete
    assert ($r.exit_code != 0) "spaces in source name should fail"

    # Invalid source name (special chars)
    let r = do -i { bootc loader-entries set-options-for-source --source "foo@bar" --options "foo=bar" } | complete
    assert ($r.exit_code != 0) "special chars in source name should fail"

    # Empty source name
    let r = do -i { bootc loader-entries set-options-for-source --source "" --options "foo=bar" } | complete
    assert ($r.exit_code != 0) "empty source name should fail"

    # Valid name with underscores/dashes
    bootc loader-entries set-options-for-source --source "my_custom-src" --options "testvalid=1"
    # Clear it immediately (no --options = remove source)
    bootc loader-entries set-options-for-source --source "my_custom-src"

    # -- Add source kargs (multiple sources before reboot) --
    bootc loader-entries set-options-for-source --source tuned --options "nohz=full isolcpus=1-3"
    bootc loader-entries set-options-for-source --source admin --options "quiet"

    # Verify the change was recorded (staged deployment on ostree,
    # in-place entry rewrite on composefs)
    assert_options_recorded "nohz=full"
    assert_options_recorded "quiet"

    print "ok: validation and initial staging"
    tmt-reboot
}

def second_boot [] {
    # Verify kargs survived the staging roundtrip
    let cmdline = parse_cmdline
    assert ("nohz=full" in $cmdline) "nohz=full should be in cmdline after reboot"
    assert ("isolcpus=1-3" in $cmdline) "isolcpus=1-3 should be in cmdline after reboot"

    # Verify both sources staged in first_boot survived
    assert ("quiet" in $cmdline) "admin quiet karg should be in cmdline after reboot"
    print "ok: multiple sources staged before reboot both survived"

    # Verify system kargs were preserved
    let system_kargs = load_system_kargs
    for karg in $system_kargs {
        assert ($karg in $cmdline) $"system karg '($karg)' must be preserved"
    }
    print "ok: system kargs preserved"

    # Verify x-options-source-* keys in BLS entry
    let source_keys = read_bls_source_keys
    let tuned_key = $source_keys | where { |line| $line starts-with "x-options-source-tuned" }
    assert (($tuned_key | length) > 0) "x-options-source-tuned should be in BLS entry"
    let tuned_line = $tuned_key | first
    assert ($tuned_line | str contains "nohz=full") "tuned source key should contain nohz=full"
    assert ($tuned_line | str contains "isolcpus=1-3") "tuned source key should contain isolcpus=1-3"
    let admin_key = $source_keys | where { |line| $line starts-with "x-options-source-admin" }
    assert (($admin_key | length) > 0) "x-options-source-admin should be in BLS entry"
    print "ok: kargs and source keys survived reboot"

    # Clean up admin source before continuing with replacement test
    bootc loader-entries set-options-for-source --source admin

    # -- Source replacement: new kargs replace old ones --
    bootc loader-entries set-options-for-source --source tuned --options "nohz=on rcu_nocbs=2-7"

    tmt-reboot
}

def third_boot [] {
    # Verify replacement worked
    let cmdline = parse_cmdline
    assert ("nohz=full" not-in $cmdline) "old nohz=full should be gone"
    assert ("isolcpus=1-3" not-in $cmdline) "old isolcpus=1-3 should be gone"
    assert ("nohz=on" in $cmdline) "new nohz=on should be present"
    assert ("rcu_nocbs=2-7" in $cmdline) "new rcu_nocbs=2-7 should be present"
    # Admin source was removed in second_boot
    assert ("quiet" not-in $cmdline) "admin quiet should be gone after removal"

    # Verify system kargs still preserved after replacement
    let system_kargs = load_system_kargs
    for karg in $system_kargs {
        assert ($karg in $cmdline) $"system karg '($karg)' must survive replacement"
    }
    print "ok: source replacement persisted, system kargs preserved"

    # -- Multiple sources coexist --
    bootc loader-entries set-options-for-source --source dracut --options "rd.driver.pre=vfio-pci"

    tmt-reboot
}

def fourth_boot [] {
    # Verify both sources persisted
    let cmdline = parse_cmdline
    assert ("nohz=on" in $cmdline) "tuned nohz=on should still be present"
    assert ("rcu_nocbs=2-7" in $cmdline) "tuned rcu_nocbs=2-7 should still be present"
    assert ("rd.driver.pre=vfio-pci" in $cmdline) "dracut karg should be present"

    # Verify both source keys in BLS
    let source_keys = read_bls_source_keys
    let tuned_keys = $source_keys | where { |line| $line starts-with "x-options-source-tuned" }
    let dracut_keys = $source_keys | where { |line| $line starts-with "x-options-source-dracut" }
    assert (($tuned_keys | length) > 0) "tuned source key should exist"
    assert (($dracut_keys | length) > 0) "dracut source key should exist"
    print "ok: multiple sources coexist"

    # -- Clear source with empty --options "" (different from no --options) --
    # --options "" should remove the kargs but the key can remain with empty value
    bootc loader-entries set-options-for-source --source dracut --options ""
    # dracut kargs should be removed from the pending state
    assert_options_cleared "rd.driver.pre=vfio-pci"
    print "ok: --options '' clears kargs"

    # Now also test no --options (remove the source entirely)
    # First re-add dracut so we can test removal
    bootc loader-entries set-options-for-source --source dracut --options "rd.driver.pre=vfio-pci"
    # Then remove it with no --options
    bootc loader-entries set-options-for-source --source dracut

    tmt-reboot
}

def fifth_boot [] {
    # Verify dracut cleared, tuned preserved
    let cmdline = parse_cmdline
    assert ("rd.driver.pre=vfio-pci" not-in $cmdline) "dracut karg should be gone"
    assert ("nohz=on" in $cmdline) "tuned nohz=on should still be present"
    assert ("rcu_nocbs=2-7" in $cmdline) "tuned rcu_nocbs=2-7 should still be present"
    print "ok: source clear persisted"

    # -- Idempotent: same kargs again should be a no-op --
    if (is_composefs) {
        # composefs edits entries in place, so a no-op must leave the
        # entry file byte-for-byte identical
        let before = open (booted_bls_entry)
        bootc loader-entries set-options-for-source --source tuned --options "nohz=on rcu_nocbs=2-7"
        let after = open (booted_bls_entry)
        assert ($before == $after) "idempotent call should not rewrite the entry"
    } else {
        bootc loader-entries set-options-for-source --source tuned --options "nohz=on rcu_nocbs=2-7"
        # Should not stage a new deployment (idempotent)
        let st = bootc status --json | from json
        assert ($st.status.staged == null) "idempotent call should not stage a deployment"
    }
    print "ok: idempotent operation"

    # -- Staged deployment interaction --
    if (is_composefs) {
        # bootc switch is not yet functional on the composefs backend; all
        # switch/upgrade plans carry fixme_skip_if_composefs upstream. Skip
        # the staged-switch interaction for the same reason. The staged-
        # entries propagation itself is covered by unit tests
        # (bootc_composefs::loader_entries).
        print "skip: staged deployment interaction (switch not yet supported on composefs)"
        tap ok
        return
    }

    # Build a derived image and switch to it (this stages a deployment).
    # Then call set-options-for-source on top. The staged deployment should
    # be replaced with one that has the new image AND the source kargs.
    bootc image copy-to-storage

    let td = mktemp -d
    $"FROM localhost/bootc
RUN echo source-test-marker > /usr/share/source-test-marker.txt
" | save $"($td)/Dockerfile"
    podman build -t localhost/bootc-source-test $"($td)"

    bootc switch --transport containers-storage localhost/bootc-source-test
    let st = bootc status --json | from json
    assert ($st.status.staged != null) "switch should stage a deployment"

    # Now add source kargs on top of the staged switch
    bootc loader-entries set-options-for-source --source tuned --options "nohz=on rcu_nocbs=2-7 skew_tick=1"

    # Verify a deployment is still staged (it was replaced, not removed)
    let st = bootc status --json | from json
    assert ($st.status.staged != null) "deployment should still be staged after set-options-for-source"

    tmt-reboot
}

def sixth_boot [] {
    # Verify the image switch landed (the derived image's marker file exists)
    assert ("/usr/share/source-test-marker.txt" | path exists) "derived image marker should exist"
    print "ok: image switch preserved"

    # Verify the source kargs also landed
    let cmdline = parse_cmdline
    assert ("nohz=on" in $cmdline) "tuned nohz=on should be present"
    assert ("rcu_nocbs=2-7" in $cmdline) "tuned rcu_nocbs=2-7 should be present"
    assert ("skew_tick=1" in $cmdline) "tuned skew_tick=1 should be present"

    # Verify source key in BLS
    let source_keys = read_bls_source_keys
    let tuned_key = $source_keys | where { |line| $line starts-with "x-options-source-tuned" }
    assert (($tuned_key | length) > 0) "tuned source key should exist after staged interaction"
    print "ok: staged deployment interaction preserved both image and source kargs"

    # Verify system kargs still intact
    let system_kargs = load_system_kargs
    let cmdline = parse_cmdline
    for karg in $system_kargs {
        assert ($karg in $cmdline) $"system karg '($karg)' must survive staged interaction"
    }
    print "ok: system kargs preserved through all phases"

    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        "2" => third_boot,
        "3" => fourth_boot,
        "4" => fifth_boot,
        "5" => sixth_boot,
        $o => { error make { msg: $"Unexpected TMT_REBOOT_COUNT ($o)" } },
    }
}
