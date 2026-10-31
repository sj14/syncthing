// Copyright (C) 2019 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package protocol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/syncthing/syncthing/internal/gen/bep"
	"github.com/syncthing/syncthing/lib/build"
	"github.com/syncthing/syncthing/lib/rand"
	"github.com/syncthing/syncthing/lib/testutil"
)

var (
	testKeyGen = NewKeyGenerator()

	// https://github.com/syncthing/syncthing/issues/8799
	cryptoIsBrokenUnderRaceDetector = (build.IsLinux || build.IsDarwin) && strings.HasPrefix(runtime.Version(), "go1.20")
)

func TestEnDecryptName(t *testing.T) {
	if cryptoIsBrokenUnderRaceDetector {
		t.Skip("cannot test")
	}

	pattern := regexp.MustCompile(
		fmt.Sprintf("^[0-9A-V]%s/[0-9A-V]{2}/([0-9A-V]{%d}/)*[0-9A-V]{1,%d}$",
			regexp.QuoteMeta(encryptedDirExtension),
			maxPathComponent, maxPathComponent-1))

	makeName := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte('a' + i%26)
		}
		return string(b)
	}

	var key [32]byte
	cases := []string{
		"",
		"foo",
		"a longer name/with/slashes and spaces",
		makeName(maxPathComponent),
		makeName(1 + maxPathComponent),
		makeName(2 * maxPathComponent),
		makeName(1 + 2*maxPathComponent),
	}
	for _, tc := range cases {
		var prev string
		for range 5 {
			enc := encryptName(tc, &key)
			if prev != "" && prev != enc {
				t.Error("name should always encrypt the same")
			}
			prev = enc
			if tc != "" && strings.Contains(enc, tc) {
				t.Error("shouldn't contain plaintext")
			}
			if !pattern.MatchString(enc) {
				t.Fatalf("encrypted name %s doesn't match %s",
					enc, pattern)
			}

			dec, err := decryptName(enc, &key)
			if err != nil {
				t.Error(err)
			}
			if dec != tc {
				t.Error("mismatch after decryption")
			}
			t.Logf("%q encrypts as %q", tc, enc)
		}
	}
}

func TestKeyDerivation(t *testing.T) {
	folderKey := testKeyGen.KeyFromPassword("my folder", "my password")
	encryptedName := encryptDeterministic([]byte("filename.txt"), folderKey, nil)
	if base32Hex.EncodeToString(encryptedName) != "3T5957I4IOA20VEIEER6JSQG0PEPIRV862II3K7LOF75Q" {
		t.Error("encrypted name mismatch")
	}

	fileKey := testKeyGen.FileKey("filename.txt", folderKey)
	// fmt.Println(base32Hex.EncodeToString(encryptBytes([]byte("hello world"), fileKey))) => A1IPD...
	const encrypted = `A1IPD28ISL7VNPRSSSQM2L31L3IJPC08283RO89J5UG0TI9P38DO9RFGK12DK0KD7PKQP6U51UL2B6H96O`
	bs, _ := base32Hex.DecodeString(encrypted)
	dec, err := DecryptBytes(bs, fileKey)
	if err != nil {
		t.Error(err)
	}
	if string(dec) != "hello world" {
		t.Error("decryption mismatch")
	}
}

func TestDecryptNameInvalid(t *testing.T) {
	key := new([32]byte)
	for _, c := range []string{
		"T.syncthing-enc/OD",
		"T.syncthing-enc/OD/",
		"T.wrong-extension/OD/PHVDD67S7FI2K5QQMPSOFSK",
		"OD/PHVDD67S7FI2K5QQMPSOFSK",
	} {
		if _, err := decryptName(c, key); err == nil {
			t.Errorf("no error for %q", c)
		}
	}
}

func TestEnDecryptBytes(t *testing.T) {
	var key [32]byte
	cases := [][]byte{
		{},
		{1, 2, 3, 4, 5},
	}
	for _, tc := range cases {
		var prev []byte
		for range 5 {
			enc := encryptBytes(tc, &key)
			if bytes.Equal(enc, prev) {
				t.Error("encryption should not repeat")
			}
			prev = enc
			if len(tc) > 0 && bytes.Contains(enc, tc) {
				t.Error("shouldn't contain plaintext")
			}
			dec, err := DecryptBytes(enc, &key)
			if err != nil {
				t.Error(err)
			}
			if !bytes.Equal(dec, tc) {
				t.Error("mismatch after decryption")
			}
		}
	}
}

func encFileInfo() FileInfo {
	return FileInfo{
		Name:        "hello",
		Size:        45,
		Permissions: 0o755,
		ModifiedS:   8080,
		Sequence:    1000,
		Blocks: []BlockInfo{
			{
				Offset: 0,
				Size:   45,
				Hash:   []byte{1, 2, 3},
			},
			{
				Offset: 45,
				Size:   45,
				Hash:   []byte{1, 2, 3},
			},
		},
	}
}

func TestEnDecryptFileInfo(t *testing.T) {
	if cryptoIsBrokenUnderRaceDetector {
		t.Skip("cannot test")
	}

	var key [32]byte
	fi := encFileInfo()

	enc := encryptFileInfo(testKeyGen, fi, &key)
	if bytes.Equal(enc.Blocks[0].Hash, enc.Blocks[1].Hash) {
		t.Error("block hashes should not repeat when on different offsets")
	}
	if enc.RawBlockSize < MinBlockSize {
		t.Error("Too small raw block size:", enc.RawBlockSize)
	}
	if enc.Sequence != fi.Sequence {
		t.Error("encrypted fileinfo didn't maintain sequence number")
	}
	again := encryptFileInfo(testKeyGen, fi, &key)
	if !bytes.Equal(enc.Blocks[0].Hash, again.Blocks[0].Hash) {
		t.Error("block hashes should remain stable (0)")
	}
	if !bytes.Equal(enc.Blocks[1].Hash, again.Blocks[1].Hash) {
		t.Error("block hashes should remain stable (1)")
	}

	// Simulate the remote setting the sequence number when writing to db
	enc.Sequence = 10

	dec, err := DecryptFileInfo(testKeyGen, enc, &key)
	if err != nil {
		t.Error(err)
	}
	if dec.Sequence != enc.Sequence {
		t.Error("decrypted fileinfo didn't maintain sequence number")
	}
	dec.Sequence = fi.Sequence
	if !reflect.DeepEqual(fi, dec) {
		t.Error("mismatch after decryption")
	}
}

func TestEncryptedFileInfoConsistency(t *testing.T) {
	if cryptoIsBrokenUnderRaceDetector {
		t.Skip("cannot test")
	}

	var key [32]byte
	files := []FileInfo{
		encFileInfo(),
		encFileInfo(),
	}
	files[1].SetIgnored()
	for i, f := range files {
		enc := encryptFileInfo(testKeyGen, f, &key)
		if err := checkFileInfoConsistency(enc); err != nil {
			t.Errorf("%v: %v", i, err)
		}
	}
}

// TestEncryptedStalemate reproduces
// https://github.com/syncthing/syncthing/issues/9884: the untrusted device
// must pull the version the trusted devices settled on.
func TestEncryptedStalemate(t *testing.T) {
	if cryptoIsBrokenUnderRaceDetector {
		t.Skip("cannot test")
	}

	const (
		devA ShortID = 10
		devB ShortID = 20
	)

	// The untrusted device has an older version with two counters
	old := encFileInfo()
	old.Version = Vector{Counters: []Counter{{ID: devA, Value: 1000}, {ID: devB, Value: 2000}}}
	old.ModifiedS = 1000

	// devA was re-added with an empty database and rescanned the file
	rescanned := encFileInfo()
	rescanned.Version = Vector{Counters: []Counter{{ID: devA, Value: 2500}}}
	rescanned.ModifiedS = 2000

	if !rescanned.Version.Concurrent(old.Version) || !rescanned.WinsConflict(old) {
		t.Fatal("expected the trusted devices to settle on the rescanned version")
	}

	// What the trusted devices announce to the untrusted device
	announced := rescanned
	if successor, ok := EncryptedSuccessor(rescanned.Version, []Vector{old.Version}); ok {
		announced.Version = successor
	}

	var key [32]byte
	have := encryptFileInfo(testKeyGen, old, &key)
	offered := encryptFileInfo(testKeyGen, announced, &key)
	if got := offered.Version.Compare(have.Version); got != Greater {
		t.Errorf("untrusted device keeps its version: offered fake version %v, it has %v", offered.Version.HumanString(), have.Version.HumanString())
	}
}

func TestEncryptedSuccessor(t *testing.T) {
	const (
		devA ShortID = 10
		devB ShortID = 20
	)
	vector := func(counters ...Counter) Vector {
		return Vector{Counters: counters}
	}

	t.Run("stuck version gets a successor", func(t *testing.T) {
		// devA was re-added with an empty database and rescanned the
		// file, while the untrusted device still has an older version
		// with a higher sum of counters
		global := vector(Counter{ID: devA, Value: 2500})
		untrusted := vector(Counter{ID: devA, Value: 1000}, Counter{ID: devB, Value: 2000})

		successor, ok := EncryptedSuccessor(global, []Vector{untrusted})
		if !ok {
			t.Fatal("expected a successor")
		}
		if got := successor.Compare(global); got != Greater {
			t.Errorf("expected successor to be Greater than the global version, got %v", got)
		}
		if got, want := encryptedVersionValue(successor), encryptedVersionValue(untrusted)+1; got != want {
			t.Errorf("expected fake version %d, got %d", want, got)
		}
		if !global.Equal(vector(Counter{ID: devA, Value: 2500})) {
			t.Errorf("global version was modified: %v", global)
		}

		again, _ := EncryptedSuccessor(global, []Vector{untrusted})
		if !again.Equal(successor) {
			t.Errorf("expected the same successor, got %v and %v", successor, again)
		}
	})

	t.Run("raises an existing counter", func(t *testing.T) {
		global := vector(Counter{ID: devA, Value: 100}, Counter{ID: encryptedSuccessorID, Value: 500})
		untrusted := vector(Counter{ID: devA, Value: 3000}, Counter{ID: devB, Value: 2000})

		successor, ok := EncryptedSuccessor(global, []Vector{untrusted})
		if !ok {
			t.Fatal("expected a successor")
		}
		if got, want := encryptedVersionValue(successor), encryptedVersionValue(untrusted)+1; got != want {
			t.Errorf("expected fake version %d, got %d", want, got)
		}
		if len(successor.Counters) != 2 {
			t.Errorf("expected two counters, got %v", successor)
		}
	})

	t.Run("highest untrusted version decides", func(t *testing.T) {
		global := vector(Counter{ID: devA, Value: 2500})
		lower := vector(Counter{ID: devB, Value: 2600})
		higher := vector(Counter{ID: devA, Value: 1000}, Counter{ID: devB, Value: 2000})

		successor, ok := EncryptedSuccessor(global, []Vector{lower, higher})
		if !ok {
			t.Fatal("expected a successor")
		}
		if got, want := encryptedVersionValue(successor), encryptedVersionValue(higher)+1; got != want {
			t.Errorf("expected fake version %d, got %d", want, got)
		}
	})

	t.Run("no successor when the untrusted device will pull", func(t *testing.T) {
		global := vector(Counter{ID: devA, Value: 1000}, Counter{ID: devB, Value: 2000})
		untrusted := vector(Counter{ID: devA, Value: 2500})

		if _, ok := EncryptedSuccessor(global, []Vector{untrusted}); ok {
			t.Error("expected no successor")
		}
	})

	t.Run("no successor without untrusted versions", func(t *testing.T) {
		global := vector(Counter{ID: devA, Value: 1000})

		if _, ok := EncryptedSuccessor(global, nil); ok {
			t.Error("expected no successor")
		}
	})
}

func TestIsEncryptedParent(t *testing.T) {
	comp := rand.String(maxPathComponent)
	cases := []struct {
		path string
		is   bool
	}{
		{"", false},
		{".", false},
		{"/", false},
		{"12" + encryptedDirExtension, false},
		{"1" + encryptedDirExtension, true},
		{"1" + encryptedDirExtension + "/b", false},
		{"1" + encryptedDirExtension + "/bc", true},
		{"1" + encryptedDirExtension + "/bcd", false},
		{"1" + encryptedDirExtension + "/bc/foo", false},
		{"1.12/22", false},
		{"1" + encryptedDirExtension + "/bc/" + comp, true},
		{"1" + encryptedDirExtension + "/bc/" + comp + "/" + comp, true},
		{"1" + encryptedDirExtension + "/bc/" + comp + "a", false},
		{"1" + encryptedDirExtension + "/bc/" + comp + "/a/" + comp, false},
	}
	for _, tc := range cases {
		if res := IsEncryptedParent(strings.Split(tc.path, "/")); res != tc.is {
			t.Errorf("%v: got %v, expected %v", tc.path, res, tc.is)
		}
	}
}

func TestEncryptedRequestInvalidOffset(t *testing.T) {
	var key [keySize]byte
	e := newEncryptedModel(nil, testKeyGen)
	e.folderKeys.keys["folder"] = &key
	for _, tc := range []struct {
		offset int64
		block  int
	}{
		{-1, 0},
		{0, 1},
		{0, -1},
		{0, int(^uint(0) >> 1)},
	} {
		_, err := e.Request(&Request{
			Folder: "folder", Name: encryptName("file", &key),
			Size: minPaddedSize + blockOverhead, Offset: tc.offset, BlockNo: tc.block,
		})
		if _, ok := errors.AsType[protocolError](err); !ok {
			t.Fatalf("offset %d block %d: expected protocol error, got %v", tc.offset, tc.block, err)
		}
	}
}

func TestDecryptInvalidFileInfo(t *testing.T) {
	var key [keySize]byte
	for _, fi := range []FileInfo{
		{Name: "file", Type: FileInfoType(-1)},
		{Name: "../file", Type: FileInfoTypeDirectory},
	} {
		enc := encryptFileInfo(testKeyGen, fi, &key)
		_, err := DecryptFileInfo(testKeyGen, enc, &key)
		if _, ok := errors.AsType[protocolError](err); !ok {
			t.Fatalf("expected protocol error, got %v", err)
		}
	}
}

func TestEncryptedShortResponse(t *testing.T) {
	var key [keySize]byte
	m := newTestModel()
	c := getRawConnection(NewConnection(c0ID, nil, nil, testutil.NoopCloser{}, m, new(mockedConnectionInfo), CompressionNever, testKeyGen))
	e := newEncryptedConnection(c, c, newFolderKeyRegistry(), testKeyGen)
	e.folderKeys.keys["folder"] = &key
	go func() {
		msg := <-c.outbox
		req := msg.msg.(*bep.Request)
		fileKey := testKeyGen.FileKey("file", &key)
		c.handleResponse(&Response{ID: int(req.Id), Data: encryptBytes([]byte("short"), fileKey)})
	}()
	_, err := e.Request(context.Background(), &Request{Folder: "folder", Name: "file", Size: 1024})
	if _, ok := errors.AsType[protocolError](err); !ok {
		t.Fatalf("expected protocol error, got %v", err)
	}
	select {
	case <-c.Closed():
	default:
		t.Fatal("connection was not closed")
	}
}
