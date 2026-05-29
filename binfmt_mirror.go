// SPDX-License-Identifier: Apache-2.0
//
// binfmt_mirror.go implements the --mirror-host-binfmt-misc startup
// behavior: read the host's binfmt_misc qemu-* registrations and write
// them as a sentinel + replay-conf at /var/lib/sysbox/binfmt-mirror.conf.
// sysbox-runc detects the sentinel and injects an OCI prestart hook
// (sysbox-binfmt-mirror.sh) into every sysbox container spec; the hook
// replays each entry into the container's per-userns binfmt_misc, then
// remounts it read-only.
//
// Why a file-based sentinel and not gRPC: the alternative (extend the
// sysbox-mgr→sysbox-runc gRPC config to carry binfmt entries) would
// require lockstep version bumps of sysbox-ipc too. The file approach
// keeps each component independently deployable — sysbox-runc just
// checks for `/var/lib/sysbox/binfmt-mirror.conf` existence and any
// content changes are picked up on the NEXT container creation without
// restarting sysbox-runc or sysbox-mgr.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	binfmtHostDir     = "/proc/sys/fs/binfmt_misc"
	binfmtMirrorDir   = "/var/lib/sysbox"
	binfmtMirrorFile  = "binfmt-mirror.conf"
	binfmtEntryPrefix = "qemu-"
)

// setupBinfmtMirror reads the host's binfmt_misc qemu-* registrations
// and writes them in writable-format to the mirror conf file consumed
// by the sysbox-binfmt-mirror.sh hook script.
//
// Called once at sysbox-mgr startup when --mirror-host-binfmt-misc is
// set. If the flag is NOT set, removeBinfmtMirror() is called instead
// so a stale conf file from a previous boot doesn't keep injecting
// hooks.
func setupBinfmtMirror() error {
	entries, err := readHostBinfmtEntries()
	if err != nil {
		return fmt.Errorf("read host binfmt entries: %w", err)
	}
	if len(entries) == 0 {
		logrus.Warn("--mirror-host-binfmt-misc set but host has no qemu-* binfmt registrations; mirror conf will be empty")
	}

	if err := writeBinfmtMirrorConf(entries); err != nil {
		return fmt.Errorf("write binfmt mirror conf: %w", err)
	}

	logrus.Infof("--mirror-host-binfmt-misc: staged %d host binfmt entries at %s/%s",
		len(entries), binfmtMirrorDir, binfmtMirrorFile)
	return nil
}

// removeBinfmtMirror deletes the sentinel conf file. Idempotent.
// Called at sysbox-mgr startup when --mirror-host-binfmt-misc is NOT
// set, so a stale file from a previous run doesn't cause sysbox-runc
// to keep injecting the hook.
func removeBinfmtMirror() {
	path := filepath.Join(binfmtMirrorDir, binfmtMirrorFile)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		logrus.Warnf("could not remove stale binfmt mirror conf %s: %v", path, err)
	}
}

// readHostBinfmtEntries scans /proc/sys/fs/binfmt_misc/qemu-* and
// converts each entry from the kernel's readback format back to the
// :name:M:offset:magic:mask:interpreter:flags format expected by the
// kernel's register-write protocol.
func readHostBinfmtEntries() ([]string, error) {
	pattern := filepath.Join(binfmtHostDir, binfmtEntryPrefix+"*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	entries := []string{}
	for _, f := range files {
		name := filepath.Base(f)
		entry, err := parseHostBinfmtEntry(f, name)
		if err != nil {
			logrus.Warnf("skipping binfmt entry %s: %v", name, err)
			continue
		}
		if entry != "" {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// parseHostBinfmtEntry reads a single /proc/sys/fs/binfmt_misc/qemu-X
// file and produces the write-format registration string.
//
// Kernel readback format (one field per line):
//
//	enabled
//	interpreter /usr/bin/qemu-aarch64-static
//	flags: POCF
//	offset 0
//	magic 7f454c460201010000000000000000000200b700
//	mask  ffffffffffffff00fffffffffffffffffeffffff
//
// Write format:
//
//	:qemu-aarch64:M:0:\x7fELF\x02\x01...:\xff\xff...:/usr/bin/qemu-aarch64-static:POCF
//
// (Type is always M for binfmt_misc qemu entries; offset 0 is the
// common case for ELF magic.)
func parseHostBinfmtEntry(path, name string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	var interp, flags, offset, magic, mask string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "enabled":
			// matched, no field
		case strings.HasPrefix(line, "interpreter "):
			interp = strings.TrimSpace(strings.TrimPrefix(line, "interpreter "))
		case strings.HasPrefix(line, "flags:"):
			flags = strings.TrimSpace(strings.TrimPrefix(line, "flags:"))
		case strings.HasPrefix(line, "offset "):
			offset = strings.TrimSpace(strings.TrimPrefix(line, "offset "))
		case strings.HasPrefix(line, "magic "):
			magic = strings.TrimSpace(strings.TrimPrefix(line, "magic "))
		case strings.HasPrefix(line, "mask "):
			mask = strings.TrimSpace(strings.TrimPrefix(line, "mask "))
		}
	}

	if interp == "" || magic == "" {
		return "", fmt.Errorf("missing required fields (interpreter=%q magic=%q)", interp, magic)
	}
	if offset == "" {
		offset = "0"
	}

	magicEsc := hexBytesToEscapedString(magic)
	maskEsc := hexBytesToEscapedString(mask)

	return fmt.Sprintf(":%s:M:%s:%s:%s:%s:%s", name, offset, magicEsc, maskEsc, interp, flags), nil
}

// hexBytesToEscapedString converts a contiguous hex string (kernel's
// readback format, e.g. "7f454c46") to the kernel's write-input format
// (\x7f\x45\x4c\x46). Each pair of hex chars becomes one \xHH escape.
// Returns empty string for empty input; the kernel accepts an empty
// mask (means "match exactly the magic bytes"), so we don't error.
func hexBytesToEscapedString(h string) string {
	if len(h) == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(h) * 2)
	for i := 0; i+1 < len(h); i += 2 {
		fmt.Fprintf(&b, "\\x%s", h[i:i+2])
	}
	return b.String()
}

// writeBinfmtMirrorConf serializes the entry list to the sentinel conf
// file consumed by the sysbox-binfmt-mirror.sh hook. Atomically:
// write to a temp file in the same directory, then rename — so that
// sysbox-runc reading the file concurrently never sees a partial write.
func writeBinfmtMirrorConf(entries []string) error {
	if err := os.MkdirAll(binfmtMirrorDir, 0755); err != nil {
		return err
	}

	var buf strings.Builder
	buf.WriteString("# Auto-generated by sysbox-mgr --mirror-host-binfmt-misc\n")
	buf.WriteString("# Existence of this file is sysbox-runc's signal to inject the\n")
	buf.WriteString("# sysbox-binfmt-mirror.sh prestart hook into every sysbox container.\n")
	buf.WriteString("# Each line is a kernel-write-format binfmt_misc registration string.\n")
	for _, e := range entries {
		buf.WriteString(e)
		buf.WriteString("\n")
	}

	final := filepath.Join(binfmtMirrorDir, binfmtMirrorFile)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, []byte(buf.String()), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}
