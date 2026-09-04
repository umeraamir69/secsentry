package main

import (
	"reflect"
	"testing"
)

func TestReorderFlagsAfterPath(t *testing.T) {
	got := reorderFlags([]string{"/tmp/repo", "--history", "--no-cache"})
	want := []string{"--history", "--no-cache", "/tmp/repo"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	got = reorderFlags([]string{"/tmp/repo", "--format", "json", "-o", "out.json"})
	want = []string{"--format", "json", "-o", "out.json", "/tmp/repo"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
