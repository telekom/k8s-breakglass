---
section: Upgrade notes
---

- The controller has the flags `--log-level` (`LOG_LEVEL`: `debug`, `info`,
  `warn`, `error`) and `--log-format` (`LOG_FORMAT`: `json`, `console`). The
  defaults, `info` and `json`, keep the current output. `--debug` is
  deprecated: it still means `--log-level=debug --log-format=console`, but
  `--debug` with `--log-format=json` now gives debug logs as JSON, and
  `--debug` with another `--log-level` stops the controller at startup.
  Replace `--debug` with `--log-level=debug` (JSON) or
  `--log-level=debug --log-format=console`. The JSON fields are documented in
  `docs/logging-and-debugging.md`.
- `docs/logging-reference.md` lists what each program logs at which level.
  `make test` fails when its generated message catalogue is out of date; run
  `go run ./hack/logref` after changing a log call.
- A panic in an HTTP handler is now logged as `[Recovery from panic]` with
  `error`, `cid`, `method` and `path`, without the request dump that included
  the request headers. client-go (klog) and Go standard-library log output now
  goes through the controller logger and uses `--log-format`.
