#!/usr/bin/env node
/**
 * Spawns the Python CLI. Does not reimplement detectors.
 */
const { spawnSync } = require("child_process");

const args = process.argv.slice(2);
let r = spawnSync("secsentry", args, { stdio: "inherit" });
if (r.error && r.error.code === "ENOENT") {
  r = spawnSync("python3", ["-m", "secsentry", ...args], { stdio: "inherit" });
}
if (r.error) {
  console.error(
    "SecSentry needs Python 3.12+ and `pip install secsentry` (or a secsentry binary on PATH)."
  );
  process.exit(1);
}
process.exit(r.status === null ? 1 : r.status);
