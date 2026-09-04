#!/usr/bin/env node
/**
 * Spawns the Go CLI. Does not reimplement detectors.
 */
const { spawnSync } = require("child_process");

const args = process.argv.slice(2);
const r = spawnSync("secsentry", args, { stdio: "inherit" });
if (r.error) {
  console.error(
    "SecSentry needs the Go binary on PATH. Install with:\n  go install github.com/umeraamir69/secsentry/cmd/secsentry@latest"
  );
  process.exit(1);
}
process.exit(r.status === null ? 1 : r.status);
