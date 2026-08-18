package runner

import (
	"bufio"
	"context"
	"io"
	"os"
	"sync"
)

type concatSource struct {
	mu       sync.Mutex
	raw      []rawItem
	files    []string
	stdin    io.Reader
	fileI    int
	scan     *bufio.Scanner
	closer   io.Closer
	scanSrc  string
	scanFile string
	line     int
	done     bool
}

func (s *concatSource) Next(ctx context.Context) (TargetSpec, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			s.closeScan()
			return TargetSpec{}, err
		}
		if len(s.raw) > 0 {
			item := s.raw[0]
			s.raw = s.raw[1:]
			return TargetSpec{Input: item.text, Source: item.source, File: item.file, Line: item.line}, nil
		}
		if s.scan != nil {
			if s.scan.Scan() {
				s.line++
				text := stringsTrimBOMSpace(s.scan.Text())
				if text == "" || hasCommentPrefix(text) {
					continue
				}
				return TargetSpec{Input: text, Source: s.scanSrc, File: s.scanFile, Line: s.line}, nil
			}
			err := s.scan.Err()
			s.closeScan()
			if err != nil {
				return TargetSpec{}, err
			}
			continue
		}
		if s.fileI < len(s.files) {
			path := s.files[s.fileI]
			s.fileI++
			f, err := os.Open(path)
			if err != nil {
				return TargetSpec{}, err
			}
			s.closer = f
			s.scan = bufio.NewScanner(f)
			s.scan.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			s.scanSrc = SourceFile
			s.scanFile = path
			s.line = 0
			continue
		}
		if s.stdin != nil {
			r := s.stdin
			s.stdin = nil
			s.scan = bufio.NewScanner(r)
			s.scan.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			s.scanSrc = SourceStdin
			s.scanFile = ""
			s.line = 0
			continue
		}
		s.closeScan()
		if s.done {
			return TargetSpec{}, io.EOF
		}
		s.done = true
		return TargetSpec{}, io.EOF
	}
}

func (s *concatSource) closeScan() {
	if s.closer != nil {
		_ = s.closer.Close()
		s.closer = nil
	}
	s.scan = nil
}

func stringsTrimBOMSpace(s string) string { return trimBOMSpace(s) }

func hasCommentPrefix(s string) bool {
	return len(s) > 0 && s[0] == '#'
}
