package metrics

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxSinkBannerBytes   = 4096
	bannerSinkBufSize    = 64 * 1024
	bannerSinkFlushEvery = 32
)

// BannerSink is an append-only JSONL file of unmatched banners.
type BannerSink struct {
	mu     sync.Mutex
	f      *os.File
	buf    *bufio.Writer
	writes int
	err    error
}

type bannerLine struct {
	TS     string `json:"ts"`
	Banner string `json:"banner"`
}

// OpenBannerSink creates or appends to path. Parent directories are created
// with artifact-like permissions (0700/0600).
func OpenBannerSink(path string) (*BannerSink, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("banner sink path is required")
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		_ = os.Chmod(dir, 0o700)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &BannerSink{f: f, buf: bufio.NewWriterSize(f, bannerSinkBufSize)}, nil
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
	if s.f == nil || s.buf == nil {
		return fmt.Errorf("banner sink closed")
	}
	if _, err = s.buf.Write(append(rec, '\n')); err != nil {
		s.err = err
		return err
	}
	s.writes++
	if s.writes%bannerSinkFlushEvery == 0 {
		if err := s.buf.Flush(); err != nil {
			s.err = err
			return err
		}
	}
	return nil
}

// Close flushes and closes the underlying file. It is safe to call twice.
func (s *BannerSink) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return s.err
	}
	var err error
	if s.buf != nil {
		err = s.buf.Flush()
		s.buf = nil
	}
	if syncErr := s.f.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := s.f.Close(); err == nil {
		err = closeErr
	}
	s.f = nil
	if err != nil {
		s.err = err
	}
	return s.err
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
