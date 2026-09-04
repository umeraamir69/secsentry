# pip package

Same version as the Go release (`VERSION` in the repo root). This console script only launches the Go CLI.

```
go install github.com/umeraamir69/secsentry/cmd/secsentry@latest
pip install secsentry
secsentry scan .
```

Requires the `secsentry` binary on PATH (`go install` or a release build). The old Python detector tree under `src/secsentry` is not this package.
