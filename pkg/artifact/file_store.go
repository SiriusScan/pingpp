package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/SiriusScan/ping++/pkg/model"
)

const (
	sha256IDPrefix = "sha256:"
	sha256HexLen   = 64
	dirPerm        = 0o700
	filePerm       = 0o600
)

// FileStoreOptions configures a persistent FileStore.
type FileStoreOptions struct {
	// MaxSize is the per-artifact cap. Zero or negative uses
	// model.DefaultArtifactMaxBytes.
	MaxSize int64
}

// FileStore is a content-addressed SHA-256 artifact store on disk.
// Blobs live at <root>/sha256/<ab>/<cd>/<full-hex-digest>.
type FileStore struct {
	root    string
	maxSize int64
	mu      sync.Mutex
}

var _ Store = (*FileStore)(nil)

// NewFileStore creates a persistent store rooted at path.
func NewFileStore(path string, opts FileStoreOptions) (*FileStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("artifact file store path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("artifact file store path: %w", err)
	}
	abs = filepath.Clean(abs)

	if err := os.MkdirAll(abs, dirPerm); err != nil {
		return nil, err
	}
	_ = os.Chmod(abs, dirPerm)

	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}

	fi, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlink as artifact store root: %s", abs)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("artifact file store path is not a directory: %s", abs)
	}

	maxSize := opts.MaxSize
	if maxSize <= 0 {
		maxSize = model.DefaultArtifactMaxBytes
	}
	return &FileStore{root: abs, maxSize: maxSize}, nil
}

// Put stores data if within size limits. Returns existing metadata on digest hit.
func (s *FileStore) Put(mediaType string, data []byte, description string) (model.Artifact, error) {
	if int64(len(data)) > s.maxSize {
		return model.Artifact{}, fmt.Errorf("artifact size %d exceeds limit %d", len(data), s.maxSize)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	blob, meta, err := s.objectPaths(digest)
	if err != nil {
		return model.Artifact{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if art, ok, err := s.existing(blob, meta, digest); err != nil {
		return model.Artifact{}, err
	} else if ok {
		return art, nil
	}

	if err := s.ensureDir(filepath.Dir(blob)); err != nil {
		return model.Artifact{}, err
	}

	art := model.Artifact{
		ID:          sha256IDPrefix + digest,
		SHA256:      digest,
		MediaType:   mediaType,
		Size:        int64(len(data)),
		CreatedAt:   time.Now().UTC(),
		Description: description,
		MaxSize:     s.maxSize,
	}
	metaBytes, err := json.Marshal(art)
	if err != nil {
		return model.Artifact{}, err
	}
	if err := writeFileAtomic(blob, data); err != nil {
		return model.Artifact{}, err
	}
	if err := writeFileAtomic(meta, metaBytes); err != nil {
		return model.Artifact{}, err
	}
	return art, nil
}

// Get retrieves by artifact ID.
func (s *FileStore) Get(id string) ([]byte, model.Artifact, error) {
	digest, err := parseSHA256Digest(id)
	if err != nil {
		return nil, model.Artifact{}, err
	}
	blob, meta, err := s.objectPaths(digest)
	if err != nil {
		return nil, model.Artifact{}, err
	}
	fi, err := lstatFile(blob)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, model.Artifact{}, fmt.Errorf("artifact not found: %s", id)
		}
		return nil, model.Artifact{}, err
	}
	data, err := os.ReadFile(blob)
	if err != nil {
		return nil, model.Artifact{}, err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, model.Artifact{}, fmt.Errorf("artifact corrupted: %s", id)
	}
	art := loadMetadata(digest, meta, fi, s.maxSize)
	art.Size = int64(len(data))
	return data, art, nil
}

// GetBySHA256 retrieves by hex digest.
func (s *FileStore) GetBySHA256(sha string) ([]byte, model.Artifact, error) {
	return s.Get(sha256IDPrefix + sha)
}

func (s *FileStore) objectPaths(digest string) (blob, meta string, err error) {
	if len(digest) != sha256HexLen {
		return "", "", fmt.Errorf("invalid artifact digest")
	}
	blob = filepath.Join(s.root, "sha256", digest[:2], digest[2:4], digest)
	meta = blob + ".meta"
	if err := s.underRoot(blob); err != nil {
		return "", "", err
	}
	if err := s.underRoot(meta); err != nil {
		return "", "", err
	}
	return blob, meta, nil
}

func (s *FileStore) underRoot(p string) error {
	cleaned := filepath.Clean(p)
	rel, err := filepath.Rel(s.root, cleaned)
	if err != nil || !filepath.IsLocal(rel) {
		return fmt.Errorf("path escapes artifact store")
	}
	return nil
}

func (s *FileStore) ensureDir(dir string) error {
	if err := s.underRoot(dir); err != nil {
		return err
	}
	rel, err := filepath.Rel(s.root, dir)
	if err != nil {
		return fmt.Errorf("path escapes artifact store")
	}
	if rel == "." {
		return refuseSymlink(s.root)
	}
	cur := s.root
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return fmt.Errorf("path escapes artifact store")
		}
		cur = filepath.Join(cur, part)
		if err := mkdirOne(cur); err != nil {
			return err
		}
	}
	return nil
}

func mkdirOne(path string) error {
	fi, err := os.Lstat(path)
	if err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in artifact store: %s", path)
		}
		if !fi.IsDir() {
			return fmt.Errorf("not a directory: %s", path)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	if err := os.Mkdir(path, dirPerm); err != nil {
		if os.IsExist(err) {
			return mkdirOne(path)
		}
		return err
	}
	_ = os.Chmod(path, dirPerm)
	return nil
}

func (s *FileStore) existing(blob, meta, digest string) (model.Artifact, bool, error) {
	fi, err := os.Lstat(blob)
	if os.IsNotExist(err) {
		return model.Artifact{}, false, nil
	}
	if err != nil {
		return model.Artifact{}, false, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return model.Artifact{}, false, fmt.Errorf("refusing symlink in artifact store: %s", blob)
	}
	if !fi.Mode().IsRegular() {
		return model.Artifact{}, false, fmt.Errorf("artifact is not a regular file: %s", blob)
	}
	return loadMetadata(digest, meta, fi, s.maxSize), true, nil
}

func loadMetadata(digest, metaPath string, blobInfo os.FileInfo, maxSize int64) model.Artifact {
	art := model.Artifact{
		ID:        sha256IDPrefix + digest,
		SHA256:    digest,
		Size:      blobInfo.Size(),
		CreatedAt: blobInfo.ModTime().UTC(),
		MaxSize:   maxSize,
	}
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return art
	}
	var stored model.Artifact
	if json.Unmarshal(raw, &stored) != nil {
		return art
	}
	if stored.SHA256 != "" && stored.SHA256 != digest {
		return art
	}
	if stored.ID != "" && stored.ID != art.ID {
		return art
	}
	art.MediaType = stored.MediaType
	art.Description = stored.Description
	if !stored.CreatedAt.IsZero() {
		art.CreatedAt = stored.CreatedAt.UTC()
	}
	if stored.MaxSize > 0 {
		art.MaxSize = stored.MaxSize
	}
	if stored.Size > 0 {
		art.Size = stored.Size
	}
	return art
}

func parseSHA256Digest(id string) (string, error) {
	if id == "" || strings.Contains(id, "..") || strings.ContainsAny(id, `/\`) {
		return "", fmt.Errorf("invalid artifact id: %q", id)
	}
	rest, ok := strings.CutPrefix(id, sha256IDPrefix)
	if !ok || len(rest) != sha256HexLen {
		return "", fmt.Errorf("invalid artifact id: %q", id)
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return "", fmt.Errorf("invalid artifact id: %q", id)
		}
	}
	return strings.ToLower(rest), nil
}

func lstatFile(path string) (os.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlink in artifact store: %s", path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("artifact is not a regular file: %s", path)
	}
	return fi, nil
}

func refuseSymlink(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink in artifact store: %s", path)
	}
	return nil
}

func writeFileAtomic(dest string, data []byte) error {
	if fi, err := os.Lstat(dest); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in artifact store: %s", dest)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	f, err := os.CreateTemp(filepath.Dir(dest), ".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	_ = f.Chmod(filePerm)
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	ok = true
	return nil
}
