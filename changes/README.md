<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Release note fragments

A pull request that needs more than its title in the changelog adds one file
here, for example upgrade notes for new CRD fields, a breaking change or a
behaviour change. Most pull requests do not need a file: the squash-merged
pull request title becomes the changelog line.

Name the file after the pull request or the topic (`changes/1522.md`,
`changes/session-toolbox.md`). The front matter names the `CHANGELOG.md`
section, the text is Markdown:

```markdown
---
section: Upgrade notes
---

- Apply the CRDs before the controller: `DebugSessionClusterBinding` has the
  new field `maxActiveSessionsPerCluster` (#1522).
```

A fragment does not replace the line from the pull request title: both are in
the release section, the fragment in its own section. Name the pull request in
the fragment text, as above, so that readers can connect the two.

Common sections: `Highlights`, `Breaking changes`, `Upgrade notes`,
`Behaviour changes`, `Security`. Another name makes a new section, and
`make changelog` prints a warning for it.

`make changelog` prints the next release section with the fragments. The
release commit (`make changelog-release`) writes them into `CHANGELOG.md` and
deletes them.
