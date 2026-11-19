---
section: Behaviour changes
---

- Recorded terminals no longer re-check authority with live API reads on every
  read and write. Input and output are admitted on a live check at most one
  second old; the stream still checks live every 500 ms and ends on the first
  failed check. A revocation now stops recorded terminal I/O within one second
  of being visible to the controller instead of on the next write. Set
  `artifacts.terminalRecordingStrictAuthorization: true` to keep the previous
  per-write checks, at the cost of throughput (about 20 KiB/s in Kind) (#1761).
- A recorded stream that loses output is never published as complete: a failed
  authority check inside the stream copy, a failed client read or write, or a
  target connection that ends without its final status (output in flight when
  the command exited) now ends the stream and publishes the recording
  incomplete with the audited `abortReason` of the fence that failed,
  `authority_check_failed`, `transport_failed` or `output_truncated` (#1760,
  #1761). A client that disconnects mid-write is usually audited as
  `transport_failed` instead of `client_disconnected`.
- A live authority check that could not complete (for example a timed-out read
  of the session, stream claim or target Pod) is audited as
  `authority_check_failed` instead of `session_authority_changed`,
  `lease_changed` or `expired`.
