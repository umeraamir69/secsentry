package gitutil

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func Run(repo string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}

func RunBytes(repo string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	return cmd.Output()
}

func IsRepo(path string) bool {
	st, err := os.Stat(filepath.Join(path, ".git"))
	return err == nil && (st.IsDir() || st.Mode().IsRegular())
}

func TrackedFiles(repo string) ([]string, error) {
	out, err := Run(repo, "ls-files", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}

type BlobRef struct {
	OID, Path, Commit, Author, Email, Timestamp string
}

func UniqueBlobs(repo string) (map[string][]byte, []BlobRef, error) {
	log, err := Run(repo, "log", "--all", "--format=%H%x00%an%x00%ae%x00%aI")
	if err != nil {
		return nil, nil, err
	}
	contents := map[string][]byte{}
	var refs []BlobRef
	for _, block := range strings.Split(log, "\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		p := strings.Split(block, "\x00")
		if len(p) < 4 {
			continue
		}
		sha, author, email, ts := p[0], p[1], p[2], p[3]
		tree, err := Run(repo, "ls-tree", "-r", "--full-tree", sha)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(tree, "\n") {
			meta, path, ok := strings.Cut(line, "\t")
			if !ok {
				continue
			}
			bits := strings.Fields(meta)
			if len(bits) < 3 || bits[1] != "blob" {
				continue
			}
			oid := bits[2]
			refs = append(refs, BlobRef{oid, path, sha, author, email, ts})
			if _, seen := contents[oid]; !seen {
				raw, err := RunBytes(repo, "cat-file", "blob", oid)
				if err != nil {
					continue
				}
				contents[oid] = raw
			}
		}
	}
	return contents, refs, nil
}

func HeadBlobOIDs(repo string) map[string]struct{} {
	out := map[string]struct{}{}
	tree, err := Run(repo, "ls-tree", "-r", "--full-tree", "HEAD")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(tree, "\n") {
		meta, _, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		bits := strings.Fields(meta)
		if len(bits) >= 3 && bits[1] == "blob" {
			out[bits[2]] = struct{}{}
		}
	}
	return out
}

func Staged(repo string) ([][2]string, error) {
	names, err := Run(repo, "diff", "--cached", "--name-only", "--diff-filter=ACMR")
	if err != nil {
		return nil, err
	}
	var pairs [][2]string
	for _, name := range strings.Split(names, "\n") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		blob, err := Run(repo, "show", ":"+name)
		if err != nil {
			continue
		}
		pairs = append(pairs, [2]string{name, blob})
	}
	return pairs, nil
}
