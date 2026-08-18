package metrics

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const maxSinkBannerBytes = 4096

// BannerSink is an append-only JSONL file of unmatched banners.
type BannerSink struct {
	mu sync.Mutex
	f  *os.File
}

type bannerLine struct {
	TS     string `json:"ts"`
	Banner string `json:"banner"`
}

// OpenBannerSink creates or appends to path. Parent directories are created.
func OpenBannerSink(path string) (*BannerSink, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("banner sink path is required")
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &BannerSink{f: f}, nil
}

// WriteBanner appends one JSONL record. Newlines in the banner are stripped.
func (s *BannerSink) WriteBanner(banner string) error {
	if s == nil {
		return nil
	}
	banner = sanitizeBanner(banner)
	if banner == "" {
		return nil
	}
	rec, err := json.Marshal(bannerLine{
		TS:     time.Now().UTC().Format(time.RFC3339Nano),
		Banner: banner,
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return fmt.Errorf("banner sink closed")
	}
	_, err = s.f.Write(append(rec, '\n'))
	if err != nil {
		return err
	}
	return s.f.Sync()
}

// Close closes the underlying file. It is safe to call twice.
func (s *BannerSink) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

func sanitizeBanner(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if len(s) <= maxSinkBannerBytes {
		return s
	}
	for len(s) > maxSinkBannerBytes {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}
