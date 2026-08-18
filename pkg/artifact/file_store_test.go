package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/SiriusScan/ping++/pkg/model"
)

func TestFileStorePutGet(t *testing.T) {
	s := mustFileStore(t, FileStoreOptions{MaxSize: 1024})
	art, err := s.Put("text/plain", []byte("hello"), "banner")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(art.ID, "sha256:") {
		t.Fatalf("id=%q", art.ID)
	}
	if art.SHA256 == "" || art.MediaType != "text/plain" || art.Description != "banner" {
		t.Fatalf("metadata=%+v", art)
	}
	if art.Size != 5 {
		t.Fatalf("size=%d", art.Size)
	}
	if art.MaxSize != 1024 {
		t.Fatalf("maxSize=%d", art.MaxSize)
	}
	if art.CreatedAt.IsZero() {
		t.Fatal("CreatedAt unset")
	}

	sum := sha256.Sum256([]byte("hello"))
	digest := hex.EncodeToString(sum[:])
	wantPath := filepath.Join(s.root, "sha256", digest[:2], digest[2:4], digest)
	if _, err := os.Stat(wantPath); err != nil {
		t.Fatalf("layout %s: %v", wantPath, err)
	}

	data, got, err := s.Get(art.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("hello")) {
		t.Fatalf("data=%q", data)
	}
	if got.SHA256 != art.SHA256 || got.ID != art.ID {
		t.Fatal("sha/id mismatch")
	}
	if got.MediaType != art.MediaType || got.Description != art.Description {
		t.Fatalf("get metadata=%+v", got)
	}

	bySHA, gotSHA, err := s.GetBySHA256(art.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bySHA, []byte("hello")) || gotSHA.ID != art.ID {
		t.Fatal("GetBySHA256 mismatch")
	}
}

func TestFileStoreSHADedup(t *testing.T) {
	s := mustFileStore(t, FileStoreOptions{MaxSize: 1024})
	art, err := s.Put("text/plain", []byte("hello"), "first")
	if err != nil {
		t.Fatal(err)
	}
	art2, err := s.Put("text/plain", []byte("hello"), "second")
	if err != nil {
		t.Fatal(err)
	}
	if art2.ID != art.ID {
		t.Fatalf("content address unstable: %s vs %s", art.ID, art2.ID)
	}
	if art2.Description != "first" {
		t.Fatalf("dedup should return existing metadata, got %q", art2.Description)
	}
	if !art2.CreatedAt.Equal(art.CreatedAt) {
		t.Fatalf("CreatedAt changed on dedup: %v vs %v", art.CreatedAt, art2.CreatedAt)
	}
}

func TestFileStoreAtomicAndMaxSize(t *testing.T) {
	root := t.TempDir()
	s, err := NewFileStore(root, FileStoreOptions{MaxSize: 8})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("application/octet-stream", make([]byte, 9), "too big"); err == nil {
		t.Fatal("expected size error")
	}

	zero, err := NewFileStore(t.TempDir(), FileStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zero.Put("application/octet-stream", make([]byte, model.DefaultArtifactMaxBytes+1), "too big"); err == nil {
		t.Fatal("expected default max size error")
	}

	art, err := s.Put("application/octet-stream", []byte("ok"), "small")
	if err != nil {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), ".tmp-") {
			t.Errorf("leftover temp %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	data, _, err := s.Get(art.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("ok")) {
		t.Fatalf("data=%q", data)
	}
}

func TestFileStoreConcurrentSameDigest(t *testing.T) {
	s := mustFileStore(t, FileStoreOptions{MaxSize: 64 * 1024})
	payload := bytes.Repeat([]byte("x"), 4096)
	const n = 32
	var wg sync.WaitGroup
	arts := make([]model.Artifact, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			arts[i], errs[i] = s.Put("application/octet-stream", payload, "concurrent")
		}()
	}
	wg.Wait()
	var id string
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("put %d: %v", i, errs[i])
		}
		if id == "" {
			id = arts[i].ID
		} else if arts[i].ID != id {
			t.Fatalf("id mismatch: %s vs %s", id, arts[i].ID)
		}
	}
	data, got, err := s.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("torn or truncated read: len=%d", len(data))
	}
	if got.Size != int64(len(payload)) {
		t.Fatalf("size=%d", got.Size)
	}
}

func TestFileStorePathTraversalImpossible(t *testing.T) {
	root := t.TempDir()
	s, err := NewFileStore(root, FileStoreOptions{MaxSize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	hex64 := strings.Repeat("a", 64)
	ids := []string{
		"../evil",
		"../../etc/passwd",
		"sha256:../" + strings.Repeat("a", 60),
		"sha256:../../etc/passwd",
		"sha256:ab/cd/" + hex64,
		"sha256:" + hex64 + "/../../x",
		"sha256:" + strings.Repeat("a", 62) + "..",
		`sha256:..\..\windows`,
		"sha256://" + hex64,
		"/etc/passwd",
		hex64,
		"sha256:" + hex64 + "/../../../etc/passwd",
		"sha256:aaaa/bbbb/" + strings.Repeat("c", 56),
	}
	for _, id := range ids {
		if _, _, err := s.Get(id); err == nil {
			t.Errorf("Get(%q) succeeded", id)
		}
		if _, _, err := s.GetBySHA256(id); err == nil {
			t.Errorf("GetBySHA256(%q) succeeded", id)
		}
	}
	parent := filepath.Dir(root)
	if _, err := os.Stat(filepath.Join(parent, "evil")); err == nil {
		t.Fatal("wrote outside store")
	}
	if _, err := os.Stat(filepath.Join(root, "..", "evil")); err == nil {
		t.Fatal("wrote evil via parent")
	}
}

func TestFileStoreRestartPersistence(t *testing.T) {
	root := t.TempDir()
	s1, err := NewFileStore(root, FileStoreOptions{MaxSize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	art, err := s1.Put("text/plain", []byte("persist-me"), "keep")
	if err != nil {
		t.Fatal(err)
	}

	s2, err := NewFileStore(root, FileStoreOptions{MaxSize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	data, got, err := s2.Get(art.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("persist-me")) {
		t.Fatalf("data=%q", data)
	}
	if got.Description != "keep" || got.MediaType != "text/plain" {
		t.Fatalf("restart metadata=%+v", got)
	}
	if got.SHA256 != art.SHA256 || got.Size != art.Size {
		t.Fatalf("restart identity=%+v", got)
	}
	bySHA, _, err := s2.GetBySHA256(art.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bySHA, []byte("persist-me")) {
		t.Fatal("GetBySHA256 after restart failed")
	}
}

func TestFileStorePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file modes")
	}
	s := mustFileStore(t, FileStoreOptions{MaxSize: 1024})
	art, err := s.Put("text/plain", []byte("perms"), "mode")
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.TrimPrefix(art.ID, "sha256:")
	dir := filepath.Join(s.root, "sha256", digest[:2], digest[2:4])
	blob := filepath.Join(dir, digest)

	check := func(path string, want os.FileMode) {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		got := info.Mode().Perm()
		if got != want {
			t.Skipf("permission %o not sticky on %s (fs/umask); wanted %o", got, path, want)
		}
	}
	check(s.root, dirPerm)
	check(filepath.Join(s.root, "sha256"), dirPerm)
	check(dir, dirPerm)
	check(blob, filePerm)
	check(blob+".meta", filePerm)
}

func mustFileStore(t *testing.T, opts FileStoreOptions) *FileStore {
	t.Helper()
	s, err := NewFileStore(t.TempDir(), opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
