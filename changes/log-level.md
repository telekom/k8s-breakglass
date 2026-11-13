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
- `bgctl` and `cluster-validator` take `--log-level` and `--log-format`
  (`LOG_LEVEL`, `LOG_FORMAT`). `bgctl` logs to stderr at `warn` in the
  `console` format by default; `--verbose` now means `--log-level=debug`, and
  its request lines use the logger format instead of `[DEBUG] [bgctl] …`.
  `cluster-validator` keeps its `cluster-validator: <error>` output (format
  `text`) by default.
- The controller no longer samples its logs. The `json` format used to keep
  only the first 100 identical lines per second and then every 100th, which
  dropped repeated authorization decisions and `audit_event` lines. Lines of
  the Go standard `log` package (for example `http: TLS handshake error`) are
  now JSON lines at `warn` with the logger name `stdlog`.
- The HTTP access log is now the controller's `http_request` line only, with
  `ip` and `user_agent` added. The `gin-contrib/zap` line, which logged the raw
  query string (OIDC `code`/`state`, approval-link `token`), is gone, and an
  `http_request` line is also written when a handler panics. The request mail
  subject (requester and group) is logged only as `subjectLength`. gRPC
  warnings and errors go through the controller logger.
- The node-maintenance `kexec-action`, `network-action` and `service-action`
  and the artifact collector `copier` and `uploader` read `LOG_LEVEL` and
  `LOG_FORMAT`. `LOG_FORMAT=json` writes their error line as JSON; the default
  output is unchanged.
