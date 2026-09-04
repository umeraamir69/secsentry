package version

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVersionMatchesFile(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(string(raw))
	if Version != want {
		t.Fatalf("version.Version=%s VERSION file=%s", Version, want)
	}
}
