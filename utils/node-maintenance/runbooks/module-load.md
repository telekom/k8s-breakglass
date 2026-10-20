<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Module load

Use `module-load` when a node misses a kernel module that its configuration
needs, for example after a router release stopped autoloading tunnel modules
(`ip6_gre`, `gre`, `ip6_tunnel`, `tunnel6`). It loads exactly one allowlisted
module of the running kernel, with the dependencies `modules.dep` lists.

* The executor adds only `SYS_MODULE` and reads the host module tree from a
  read-only `/lib/modules` mount. It ignores `modprobe.d` completely (no
  `install`/`remove` commands, and also none of the node's `options` or
  `softdep` lines) and passes no module parameters; only kernel command-line
  `module.param=` values apply. A module whose defaults create devices or
  change tunables is loaded with those defaults.
* The load lasts until the next reboot. Persist the module through the node
  configuration (for example `modules-load.d` through your image or a reviewed
  configuration change); a replacement node otherwise has the same problem.
* A module that is already loaded is recorded and left unchanged.

Evidence under `/evidence/module-load-*`: `before-depends.txt` (the module
files modprobe would load), `action-modprobe.txt`, and `metadata` with the
kernel release and whether `/sys/module/<module>` exists afterwards. If the
result is `failed`, do not retry in a loop; check that the module exists for
the running kernel and replace or reconfigure the node.
