// Package artifact provides bounded, content-addressed evidence storage
// so scans can be fingerprinted repeatedly without re-touching the network.
package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/SiriusScan/ping++/pkg/model"
)

// Store persists raw evidence blobs.
type Store interface {
	Put(mediaType string, data []byte, description string) (model.Artifact, error)
	Get(id string) ([]byte, model.Artifact, error)
	GetBySHA256(sha string) ([]byte, model.Artifact, error)
}

// MemoryStore is an in-memory SHA-256 content-addressed store with size limits.
type MemoryStore struct {
	mu      sync.RWMutex
	maxSize int64
	blobs   map[string][]byte
	meta    map[string]model.Artifact
}

// NewMemoryStore creates a store with the given per-artifact max size.
func NewMemoryStore(maxSize int64) *MemoryStore {
	if maxSize <= 0 {
		maxSize = model.DefaultArtifactMaxBytes
	}
	return &MemoryStore{
		maxSize: maxSize,
		blobs:   make(map[string][]byte),
		meta:    make(map[string]model.Artifact),
	}
}

// Put stores data if within size limits. Returns existing metadata on digest hit.
func (s *MemoryStore) Put(mediaType string, data []byte, description string) (model.Artifact, error) {
	if int64(len(data)) > s.maxSize {
		return model.Artifact{}, fmt.Errorf("artifact size %d exceeds limit %d", len(data), s.maxSize)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	id := "sha256:" + digest

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.meta[id]; ok {
		return existing, nil
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	art := model.Artifact{
		ID:          id,
		SHA256:      digest,
		MediaType:   mediaType,
		Size:        int64(len(data)),
		CreatedAt:   time.Now().UTC(),
		Description: description,
		MaxSize:     s.maxSize,
	}
	s.blobs[id] = cp
	s.meta[id] = art
	return art, nil
}

// Get retrieves by artifact ID.
func (s *MemoryStore) Get(id string) ([]byte, model.Artifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	art, ok := s.meta[id]
	if !ok {
		return nil, model.Artifact{}, fmt.Errorf("artifact not found: %s", id)
	}
	return append([]byte(nil), s.blobs[id]...), art, nil
}

// GetBySHA256 retrieves by hex digest.
func (s *MemoryStore) GetBySHA256(sha string) ([]byte, model.Artifact, error) {
	return s.Get("sha256:" + sha)
}
