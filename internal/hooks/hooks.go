package hooks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const marker = "SecSentry pre-commit"

const hook = `#!/bin/sh
# SecSentry pre-commit
# Blocks commits that stage a HIGH or CRITICAL secret.
# Bypass (logged in history, use sparingly): git commit --no-verify

secsentry scan --staged --fail-on high || {
  echo ""
  echo "SecSentry blocked this commit."
  echo "Rotate anything real, then remove it from the staged change."
  echo "Values above are masked; the file and line show you where to look."
  exit 1
}
`

func Install(repo string) error {
	path := filepath.Join(repo, ".git", "hooks", "pre-commit")
	if raw, err := os.ReadFile(path); err == nil && !strings.Contains(string(raw), marker) {
		backup := path + ".secsentry-backup"
		if err := os.WriteFile(backup, raw, 0o755); err != nil {
			return err
		}
		fmt.Printf("Existing hook backed up to %s\n", backup)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(hook), 0o755); err != nil {
		return err
	}
	fmt.Printf("Installed %s\n", path)
	return nil
}

func Uninstall(repo string) error {
	path := filepath.Join(repo, ".git", "hooks", "pre-commit")
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("No pre-commit hook found.")
		return nil
	}
	if !strings.Contains(string(raw), marker) {
		fmt.Println("Pre-commit hook was not installed by SecSentry; leaving it alone.")
		return nil
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	fmt.Printf("Removed %s\n", path)
	return nil
}
