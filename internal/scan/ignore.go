package scan

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/umeraamir69/secsentry/internal/gitutil"
)

const (
	ignoreFile    = ".secsentryignore"
	allowlistFile = ".secsentryallow"
)

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".venv": true, "venv": true,
	"__pycache__": true, "dist": true, "build": true,
	".mypy_cache": true, ".pytest_cache": true, ".ruff_cache": true,
	".secsentry": true,
}

type ignores struct {
	patterns []string
}

func loadPatterns(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

func loadIgnores(repo string) ignores {
	return ignores{patterns: loadPatterns(filepath.Join(repo, ignoreFile))}
}

func (ig ignores) match(rel string) bool {
	rel = strings.ReplaceAll(rel, "\\", "/")
	base := filepath.Base(rel)
	for _, pat := range ig.patterns {
		if ok, _ := filepath.Match(pat, rel); ok {
			return true
		}
		if ok, _ := filepath.Match(pat, base); ok {
			return true
		}
		if strings.HasSuffix(pat, "/") && strings.HasPrefix(rel, pat) {
			return true
		}
		if strings.Contains(rel, pat) && strings.ContainsAny(pat, "*?[") {
			continue
		}
	}
	return false
}

func loadAllowlist(repo string) []string {
	var out []string
	for _, p := range loadPatterns(filepath.Join(repo, allowlistFile)) {
		fp := strings.Fields(p)[0]
		if fp != "" {
			out = append(out, strings.ToLower(fp))
		}
	}
	return out
}

func isAllowlisted(fingerprint string, allowed []string) bool {
	fp := strings.ToLower(fingerprint)
	for _, a := range allowed {
		if a != "" && strings.HasPrefix(fp, a) {
			return true
		}
	}
	return false
}

func skippedPath(rel string) bool {
	for _, part := range strings.Split(strings.ReplaceAll(rel, "\\", "/"), "/") {
		if skipDirs[part] {
			return true
		}
	}
	return false
}

func candidatePaths(root string) []string {
	if gitutil.IsRepo(root) {
		if tracked, err := gitutil.TrackedFiles(root); err == nil && tracked != nil {
			return tracked
		}
	}
	var out []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if skippedPath(rel) {
			return nil
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	return out
}
