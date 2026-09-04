# Security

- **Never** open an issue with a live secret. Rotate it, then describe the detector miss with a **fake** lookalike.
- SecSentry does not send secrets to vendor APIs (no “is this key still valid?” calls).
- GitHub Action comments and JSON reports are **masked**.
- Eval corpus uses planted, non-live values only.

Report tooling bugs via GitHub Issues on this repository.
