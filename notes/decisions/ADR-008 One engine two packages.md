---
tags:
  - adr
status: accepted
date: 2026-09-04
---

# ADR-008 One engine, Go binary

## Context

v1 shipped a Python engine and an npm wrapper that spawned it. Converting the product to Go means we must not keep two detector implementations. Duplicating rules in Python and Go would drift and double the false-positive work.

## Decision

- The **Go module** (`github.com/umeraamir69/secsentry`) is the engine and the CLI
- Install path is `go install github.com/umeraamir69/secsentry/cmd/secsentry@latest`
- npm package `secsentry` and PyPI package `secsentry` are **PATH wrappers** that invoke that CLI
- The GitHub Action builds the Go binary with `setup-go`
- Same version number in `VERSION`, `internal/version/version.go`, `packages/npm/package.json`, and `pyproject.toml`

## Consequences

- Node users need the Go binary on PATH (document clearly in the npm README)
- One test suite (`go test ./...`) covers detection
- The older Python tree is not the product engine

## Related

- [[Dual packaging]]
- [[ADR-001 Package name]]
- [[Decisions]]
