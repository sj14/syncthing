// Copyright (C) 2018 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package model

import (
	"bytes"
	"cmp"
	"context"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/d4l3k/messagediff"

	"github.com/syncthing/syncthing/lib/build"
	"github.com/syncthing/syncthing/lib/config"
	"github.com/syncthing/syncthing/lib/events"
	"github.com/syncthing/syncthing/lib/fs"
	"github.com/syncthing/syncthing/lib/protocol"
	"github.com/syncthing/syncthing/lib/rand"
)

type unifySubsCase struct {
	in     []string // input to unifySubs
	exists []string // paths that exist in the database
	out    []string // expected output
}

func unifySubsCases() []unifySubsCase {
	cases := []unifySubsCase{
		{
			// 0. trailing slashes are cleaned, known paths are just passed on
			[]string{"foo/", "bar//"},
			[]string{"foo", "bar"},
			[]string{"bar", "foo"}, // the output is sorted
		},
		{
			// 1. "foo/bar" gets trimmed as it's covered by foo
			[]string{"foo", "bar/", "foo/bar/"},
			[]string{"foo", "bar"},
			[]string{"bar", "foo"},
		},
		{
			// 2. "" gets simplified to the empty list; ie scan all
			[]string{"foo", ""},
			[]string{"foo"},
			nil,
		},
		{
			// 3. "foo/bar" is unknown, but it's kept
			// because its parent is known
			[]string{"foo/bar"},
			[]string{"foo"},
			[]string{"foo/bar"},
		},
		{
			// 4. two independent known paths, both are kept
			// "usr/lib" is not a prefix of "usr/libexec"
			[]string{"usr/lib", "usr/libexec"},
			[]string{"usr", "usr/lib", "usr/libexec"},
			[]string{"usr/lib", "usr/libexec"},
		},
		{
			// 5. "usr/lib" is a prefix of "usr/lib/exec"
			[]string{"usr/lib", "usr/lib/exec"},
			[]string{"usr", "usr/lib", "usr/libexec"},
			[]string{"usr/lib"},
		},
		{
			// 6. .stignore and .stfolder are special and are passed on
			// verbatim even though they are unknown
			[]string{config.DefaultMarkerName, ".stignore"},
			[]string{},
			[]string{config.DefaultMarkerName, ".stignore"},
		},
		{
			// 7. but the presence of something else unknown forces an actual
			// scan
			[]string{config.DefaultMarkerName, ".stignore", "foo/bar"},
			[]string{},
			[]string{config.DefaultMarkerName, ".stignore", "foo"},
		},
		{
			// 8. explicit request to scan all
			nil,
			[]string{"foo"},
			nil,
		},
		{
			// 9. empty list of subs
			[]string{},
			[]string{"foo"},
			nil,
		},
		{
			// 10. absolute path
			[]string{"/foo"},
			[]string{"foo"},
			[]string{"foo"},
		},
	}

	if build.IsWindows {
		// Fixup path separators
		for i := range cases {
			for j, p := range cases[i].in {
				cases[i].in[j] = filepath.FromSlash(p)
			}
			for j, p := range cases[i].exists {
				cases[i].exists[j] = filepath.FromSlash(p)
			}
			for j, p := range cases[i].out {
				cases[i].out[j] = filepath.FromSlash(p)
			}
		}
	}

	return cases
}

func TestUnifySubs(t *testing.T) {
	cases := unifySubsCases()
	for i, tc := range cases {
		exists := func(f string) bool {
			return slices.Contains(tc.exists, f)
		}
		out := unifySubs(tc.in, exists)
		if diff, equal := messagediff.PrettyDiff(tc.out, out); !equal {
			t.Errorf("Case %d failed; got %v, expected %v, diff:\n%s", i, out, tc.out, diff)
		}
	}
}

func BenchmarkUnifySubs(b *testing.B) {
	cases := unifySubsCases()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tc := range cases {
			exists := func(f string) bool {
				return slices.Contains(tc.exists, f)
			}
			unifySubs(tc.in, exists)
		}
	}
}

func TestSetPlatformData(t *testing.T) {
	// Checks that setPlatformData runs without error when applied to a temp
	// file, named differently than the given FileInfo.

	fs := fs.NewFilesystem(fs.FilesystemTypeFake, rand.String(32))
	if fd, err := fs.Create("file.tmp"); err != nil {
		t.Fatal(err)
	} else {
		fd.Close()
	}

	xattr := []protocol.Xattr{{Name: "user.foo", Value: []byte("bar")}}
	fi := &protocol.FileInfo{
		Name:        "should be ignored",
		Permissions: 0o400,
		ModifiedS:   1234567890,
		Platform: protocol.PlatformData{
			Linux:   &protocol.XattrData{Xattrs: xattr},
			Darwin:  &protocol.XattrData{Xattrs: xattr},
			FreeBSD: &protocol.XattrData{Xattrs: xattr},
			NetBSD:  &protocol.XattrData{Xattrs: xattr},
		},
	}

	// Minimum required to support setPlatformData
	sr := &sendReceiveFolder{
		folder: &folder{
			FolderConfiguration: config.FolderConfiguration{
				SyncXattrs: true,
			},
			mtimefs: fs,
		},
	}

	if err := sr.setPlatformData(fi, "file.tmp"); err != nil {
		t.Error(err)
	}
}

func TestEncryptedSuccessors(t *testing.T) {
	setup := func(t *testing.T, untrusted bool) *sendReceiveFolder {
		t.Helper()
		_, f := setupSendReceiveFolder(t)
		found := false
		for i := range f.Devices {
			if f.Devices[i].DeviceID == device1 {
				found = true
				if untrusted {
					f.Devices[i].EncryptionPassword = "secret"
				}
			}
		}
		if !found {
			t.Fatal("device1 is not part of the folder")
		}
		return f
	}

	vector := func(counters ...protocol.Counter) protocol.Vector {
		slices.SortFunc(counters, func(a, b protocol.Counter) int {
			return cmp.Compare(a.ID, b.ID)
		})
		return protocol.Vector{Counters: counters}
	}

	// writeFiles writes the local file as the global version and the
	// version of the remote device1, which loses against it by
	// modification time
	writeFiles := func(t *testing.T, f *sendReceiveFolder, local, remote protocol.Vector) (protocol.FileInfo, protocol.FileInfo) {
		t.Helper()
		file := createEmptyFileInfo(t, "foo", f.Filesystem())
		file.Version = local
		must(t, f.updateLocalsFromScanning([]protocol.FileInfo{file}))

		remoteFile := file
		remoteFile.Version = remote
		remoteFile.ModifiedS = file.ModifiedS - 10
		must(t, f.db.Update(f.folderID, device1, []protocol.FileInfo{remoteFile}))

		global, ok, err := f.db.GetGlobalFile(f.folderID, "foo")
		must(t, err)
		if !ok || !global.Version.Equal(local) {
			t.Fatalf("expected the local file to be global, got %v", global.Version)
		}
		return file, remoteFile
	}

	handle := func(t *testing.T, f *sendReceiveFolder) protocol.FileInfo {
		t.Helper()
		f.ScheduleEncryptedSuccessors([]string{"foo"})
		must(t, f.handleEncryptedSuccessors(context.Background()))
		file, ok, err := f.db.GetDeviceFile(f.folderID, protocol.LocalDeviceID, "foo")
		must(t, err)
		if !ok {
			t.Fatal("local file is missing")
		}
		return file
	}

	// The local file is the global version after a rescan with an empty
	// database; the remote has an older version with a higher sum of
	// counters
	rescanned := vector(protocol.Counter{ID: myID.Short(), Value: 2500})
	older := vector(protocol.Counter{ID: myID.Short(), Value: 1000}, protocol.Counter{ID: device2.Short(), Value: 2000})

	t.Run("stuck file gets a successor", func(t *testing.T) {
		f := setup(t, true)
		file, _ := writeFiles(t, f, rescanned, older)

		bumped := handle(t, f)
		if got := bumped.Version.Compare(file.Version); got != protocol.Greater {
			t.Fatalf("expected a Greater version, got %v (%v)", got, bumped.Version)
		}
		if bumped.ModifiedS != file.ModifiedS || bumped.Size != file.Size || !bytes.Equal(bumped.BlocksHash, file.BlocksHash) {
			t.Error("expected only the version to change")
		}

		// The successor is enough, no further one is created
		if again := handle(t, f); !again.Version.Equal(bumped.Version) {
			t.Errorf("expected no further successor, got %v", again.Version)
		}
	})

	t.Run("received index schedules the check", func(t *testing.T) {
		f := setup(t, true)
		file, remoteFile := writeFiles(t, f, rescanned, older)

		s := &indexHandler{
			conn:              device1Conn,
			downloads:         newDeviceDownloadState(),
			folder:            f.folderID,
			remoteIsUntrusted: true,
			evLogger:          events.NoopLogger,
			sdb:               f.db,
			runner:            f,
			cond:              sync.NewCond(new(sync.Mutex)),
		}
		must(t, s.receive([]protocol.FileInfo{remoteFile}, true, "test", 0, 0))

		must(t, f.handleEncryptedSuccessors(context.Background()))
		bumped, _, err := f.db.GetDeviceFile(f.folderID, protocol.LocalDeviceID, "foo")
		must(t, err)
		if got := bumped.Version.Compare(file.Version); got != protocol.Greater {
			t.Errorf("expected a Greater version, got %v (%v)", got, bumped.Version)
		}
	})

	t.Run("trusted remote", func(t *testing.T) {
		f := setup(t, false)
		file, _ := writeFiles(t, f, rescanned, older)

		if got := handle(t, f); !got.Version.Equal(file.Version) {
			t.Errorf("expected no successor, got %v", got.Version)
		}
	})

	t.Run("untrusted device will pull", func(t *testing.T) {
		f := setup(t, true)
		lower := vector(protocol.Counter{ID: myID.Short(), Value: 1000})
		file, _ := writeFiles(t, f, rescanned, lower)

		if got := handle(t, f); !got.Version.Equal(file.Version) {
			t.Errorf("expected no successor, got %v", got.Version)
		}
	})
}
