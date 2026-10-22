#!/bin/bash
# sysbox-binfmt-mirror.sh
#
# OCI prestart hook that mirrors the host's binfmt_misc qemu registrations
# into the container's per-user-namespace binfmt_misc instance, then
# remounts that instance read-only. Net effect: the container has working
# cross-arch QEMU emulation matching the host's POCF F-flag handlers, AND
# any in-pod attempt to register/overwrite (e.g., docker/setup-qemu-action
# running tonistiigi/binfmt --install all) fails with EROFS — preserving
# our entries instead of getting clobbered.
#
# Installed by sysbox-mgr's Makefile to /usr/bin/sysbox-binfmt-mirror.sh.
# Wired in by sysbox-runc's ConvertSpec(): when sysbox-mgr is running
# with --mirror-host-binfmt-misc, it writes a sentinel + entries file
# at /var/lib/sysbox/binfmt-mirror.conf, and sysbox-runc detects that
# sentinel and appends this script as a prestart hook to every sysbox
# container spec.
#
# Hook protocol: runc invokes us with OCI hook state JSON on stdin
# (we extract .pid). Hook environment is the host's; we nsenter into
# the container's mount namespace to interact with its binfmt_misc fs.
#
# Failures are best-effort by design — individual entry replay failures
# (already-registered, malformed) are logged but don't fail the hook
# (which would block container start for every sysbox container). Hook
# only returns non-zero if a prerequisite step (jq missing, mount
# namespace inaccessible) catastrophically fails.

set -uo pipefail

CONF=/run/sysbox-binfmt-mirror.conf
LOG_TAG="sysbox-binfmt-mirror"

log() { echo "${LOG_TAG}: $*" >&2; }

# Sentinel: if sysbox-mgr isn't running with --mirror-host-binfmt-misc,
# the conf file is absent. Hook is a no-op — exit clean so we don't
# block container creation.
if [[ ! -f "$CONF" ]]; then
    log "no $CONF — nothing to mirror, skipping"
    exit 0
fi

# Read OCI state from stdin, extract container PID. jq is part of the
# AMI; if it's missing something is wrong with the host setup.
if ! command -v jq >/dev/null 2>&1; then
    log "jq not found — required for parsing OCI hook state"
    exit 1
fi

STATE=$(cat)
PID=$(echo "$STATE" | jq -r '.pid // empty')
if [[ -z "$PID" || "$PID" == "null" ]]; then
    log "no .pid in OCI hook state, skipping"
    exit 0
fi

MNTNS="/proc/${PID}/ns/mnt"
if [[ ! -e "$MNTNS" ]]; then
    log "$MNTNS not found (container PID=${PID} already gone?), skipping"
    exit 0
fi

# Sanity: container should have binfmt_misc mounted by sysbox-mgr's
# default auto-mount. If not, attempt to mount (best-effort).
if ! nsenter --mount="$MNTNS" -- mountpoint -q /proc/sys/fs/binfmt_misc 2>/dev/null; then
    log "binfmt_misc not mounted in container PID=${PID} — attempting mount"
    if ! nsenter --mount="$MNTNS" -- mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc 2>/dev/null; then
        log "failed to mount binfmt_misc in container — cross-arch will not work"
        exit 0  # don't block container; just lose cross-arch support for this pod
    fi
fi

# Replay each entry. Lines beginning with # or blank are skipped.
# Format per line: :name:M:offset:magic:mask:interpreter:flags
# (See Linux Documentation/admin-guide/binfmt-misc.rst for the syntax.)
COUNT_OK=0
COUNT_SKIP=0
while IFS= read -r entry; do
    # Skip comments + blank lines
    if [[ -z "$entry" || "${entry:0:1}" == "#" ]]; then
        continue
    fi
    # Write the entry to the container's register file via nsenter.
    # Using printf '%s' to avoid escape interpretation — kernel's
    # binfmt_misc parser handles \xHH literally in the input bytes.
    if nsenter --mount="$MNTNS" -- sh -c "printf '%s' '$entry' > /proc/sys/fs/binfmt_misc/register" 2>/dev/null; then
        COUNT_OK=$((COUNT_OK + 1))
    else
        # Most likely cause: entry already registered (EEXIST). Not fatal.
        COUNT_SKIP=$((COUNT_SKIP + 1))
    fi
done < "$CONF"
log "replayed ${COUNT_OK} entries into container PID=${PID} (${COUNT_SKIP} skipped, likely already present)"

# Remount binfmt_misc read-only inside the container. After this, any
# in-pod tonistiigi/binfmt --install (e.g., from docker/setup-qemu-action)
# fails with EROFS at the write-to-register step instead of overwriting
# our entries with non-P-flag registrations. The pod keeps the working
# POCF entries we just replayed.
if nsenter --mount="$MNTNS" -- mount -o remount,ro /proc/sys/fs/binfmt_misc 2>/dev/null; then
    log "remounted /proc/sys/fs/binfmt_misc as ro inside container PID=${PID}"
else
    log "remount-ro of /proc/sys/fs/binfmt_misc failed (non-fatal — entries still active)"
fi

exit 0
