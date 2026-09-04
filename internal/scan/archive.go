package scan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	maxArchiveBytes = 8_000_000
	maxMemberBytes  = 1_000_000
	maxArchiveDepth = 2
	maxMembers      = 80
)

func looksArchive(name string, data []byte) bool {
	if len(data) < 4 || len(data) > maxArchiveBytes {
		return false
	}
	low := strings.ToLower(name)
	if strings.HasSuffix(low, ".tar") || strings.HasSuffix(low, ".tar.gz") || strings.HasSuffix(low, ".tgz") {
		return true
	}
	if data[0] == 'P' && data[1] == 'K' {
		return true
	}
	if data[0] == 0x1f && data[1] == 0x8b {
		return true
	}
	switch filepath.Ext(low) {
	case ".zip", ".whl", ".jar", ".gz":
		return true
	}
	return false
}

func asUTF8(data []byte) string {
	if len(data) == 0 || len(data) > maxMemberBytes || bytesContainNUL(data) {
		return ""
	}
	if !utf8.Valid(data) {
		return ""
	}
	return string(data)
}

func walkArchive(data []byte, name string, depth int) [][2]string {
	if depth > maxArchiveDepth || !looksArchive(name, data) {
		return nil
	}
	var found [][2]string
	add := func(inner string, payload []byte) {
		if len(found) >= maxMembers {
			return
		}
		label := name + "!" + inner
		if t := asUTF8(payload); t != "" {
			found = append(found, [2]string{label, t})
		} else if looksArchive(inner, payload) {
			found = append(found, walkArchive(payload, label, depth+1)...)
		}
	}

	if len(data) >= 2 && data[0] == 'P' && data[1] == 'K' {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return found
		}
		for i, f := range zr.File {
			if i >= maxMembers || f.FileInfo().IsDir() || f.UncompressedSize64 > maxMemberBytes {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			payload, _ := io.ReadAll(io.LimitReader(rc, maxMemberBytes+1))
			rc.Close()
			add(f.Name, payload)
		}
		return found
	}

	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return found
		}
		unpacked, err := io.ReadAll(io.LimitReader(gr, maxArchiveBytes))
		gr.Close()
		if err != nil {
			return found
		}
		if t := asUTF8(unpacked); t != "" && !looksArchive(name, unpacked) {
			found = append(found, [2]string{name + "!(decompressed)", t})
			return found
		}
		return walkArchive(unpacked, name, depth)
	}

	tr := tar.NewReader(bytes.NewReader(data))
	for i := 0; i < maxMembers; i++ {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if !hdr.FileInfo().Mode().IsRegular() || hdr.Size > maxMemberBytes {
			continue
		}
		payload, _ := io.ReadAll(io.LimitReader(tr, maxMemberBytes+1))
		add(hdr.Name, payload)
	}
	return found
}
