---
tags:
  - architecture
  - quality
---

# False positives

Goal is not "detect everything." Goal is **likely secrets, low noise**.

## Must not fire HIGH on

- SHA hashes
- UUIDs
- Random IDs
- CSS hashes
- Minified JS
- `package-lock.json`
- Test fixtures (configurable)
- Documentation examples (`YOUR_API_KEY_HERE`, `AKIAIOSFODNN7EXAMPLE`)
- `password = "password"`

## Tests

Fixtures under `tests/fixtures/`: aws, github, jwt, private_key, generic, false_positive, high_entropy.

## Related

- [[Detection engine]]
- [[Finding model]]
