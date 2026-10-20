# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0
"""Tests for hack/changelog.py. Run: python3 -B hack/changelog_test.py"""

import contextlib
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import changelog  # noqa: E402

FROZEN = """Intro text.

### Behaviour behind `X`

- legacy (#5)

### Fixes

- hand-written fix (#1)
- hand-written fix with a link ([#6](https://github.com/telekom/k8s-breakglass/pull/6))
"""


def entry(group, scope, message):
    pr = changelog.TITLE_PR.search(message)
    return (group, changelog.entry_line(scope, message), pr and pr.group(1))


class RenderTest(unittest.TestCase):
    def test_merge(self):
        entries = [
            entry("Fixes", "gobgp", "already listed (#1)"),
            entry("Fixes", "gobgp", "already listed as a link (#6)"),
            entry("Fixes", "gobgp", "new fix (#2)"),
            entry("Features", None, "new feature (#3)"),
            entry("Dependencies", "deps", "bump x from 1 to 2 (#4)"),
            entry("Dependencies", "deps-dev", "bump y (#7)"),
        ]
        frags = [("Upgrade notes", "- check the CRDs"), ("Breaking changes", "- removed Y")]
        self.assertEqual(
            changelog.render(FROZEN, entries, frags),
            """Intro text.

### Behaviour behind `X`

- legacy (#5)

### Breaking changes

- removed Y

### Upgrade notes

- check the CRDs

### Features

- new feature ([#3](https://github.com/telekom/k8s-breakglass/pull/3))

### Fixes

- hand-written fix (#1)
- hand-written fix with a link ([#6](https://github.com/telekom/k8s-breakglass/pull/6))
- gobgp: new fix ([#2](https://github.com/telekom/k8s-breakglass/pull/2))

### Dependencies

- bump x from 1 to 2 ([#4](https://github.com/telekom/k8s-breakglass/pull/4))
- bump y ([#7](https://github.com/telekom/k8s-breakglass/pull/7))""",
        )

    def test_dedup_uses_the_title_pr_only(self):
        # "#5" inside the title is not the PR of the commit; #16 is.
        entries = [entry("Fixes", None, "fix issue #5 again (#16)")]
        self.assertIn("pull/16", changelog.render(FROZEN, entries, []))
        entries = [entry("Fixes", None, "fix issue #16 again (#5)")]
        self.assertNotIn("again", changelog.render(FROZEN, entries, []))

    def test_unknown_fragment_section_warns(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            changelog.render("", [], [("Odd section", "- x"), ("Breaking changes", "- y")])
        self.assertIn("'Odd section'", err.getvalue())
        self.assertNotIn("Breaking", err.getvalue())

    def test_empty(self):
        self.assertEqual(changelog.render("", [], []), "No changes.")


class CheckPRTest(unittest.TestCase):
    def test_changelog_edit_needs_release_title(self):
        self.assertIsNone(changelog.check_pr(["pkg/a.go", "changes/1.md"], "feat: x"))
        self.assertIn("do not edit", changelog.check_pr(["CHANGELOG.md"], "feat: x"))
        self.assertIn("do not edit", changelog.check_pr(["CHANGELOG.md"], "chore: prepare v0.3.0 release"))
        self.assertIn("do not edit", changelog.check_pr(["CHANGELOG.md"], "chore(release): v0.3.0 and more"))
        self.assertIsNone(changelog.check_pr(["CHANGELOG.md"], "chore(release): v0.3.0-rc.14"))
        self.assertIsNone(changelog.check_pr(["CHANGELOG.md"], "chore(release): v0.3.0"))
        self.assertIsNone(changelog.check_pr(["CHANGELOG.md", "hack/changelog.py"], "chore: x"))
        self.assertIsNone(changelog.check_pr(["CHANGELOG.md", "cliff.toml"], "ci(release): x"))
        self.assertIn("do not edit", changelog.check_pr(["CHANGELOG.md", "cliff.toml"], "feat: x"))

    def test_title_must_be_conventional(self):
        for title in ["feat(debug): x", "fix: y", "deps(go): bump z", "feat(api)!: drop w", "revert: feat: v"]:
            self.assertIsNone(changelog.check_pr(["pkg/a.go"], title), title)
        for title in ["Restore CLI completion", "feat:x", "Feat: x", "", "feat(debug) x"]:
            self.assertIn("Conventional Commit", changelog.check_pr(["pkg/a.go"], title), title)


class ReleaseTest(unittest.TestCase):
    def test_release(self):
        text = """# Changelog

## [Unreleased]

old text

## [0.1.0] - 2026-01-01

- a

[Unreleased]: https://github.com/telekom/k8s-breakglass/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/telekom/k8s-breakglass/releases/tag/v0.1.0
"""
        out = changelog.release("0.2.0", "- b", text, "2026-02-02", "v0.1.0")
        self.assertEqual(
            out,
            """# Changelog

## [Unreleased]

## [0.2.0] - 2026-02-02

- b

## [0.1.0] - 2026-01-01

- a

[Unreleased]: https://github.com/telekom/k8s-breakglass/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/telekom/k8s-breakglass/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/telekom/k8s-breakglass/releases/tag/v0.1.0
""",
        )
        span = changelog.find_section(out, "0.2.0")
        assert span
        self.assertEqual(out[span[0]:span[1]].strip(), "- b")
        with self.assertRaisesRegex(SystemExit, r"already has a '## \[0.2.0\]'"):
            changelog.release("0.2.0", "- b", out, "2026-02-02", "v0.1.0")

    def test_missing_unreleased(self):
        text = "# Changelog\n\n## [0.1.0] - 2026-01-01\n"
        with self.assertRaisesRegex(SystemExit, "no '## \\[Unreleased\\]'"):
            changelog.release("0.2.0", "- b", text, "2026-02-02", "v0.1.0")
        with self.assertRaisesRegex(SystemExit, "no '## \\[Unreleased\\]'"):
            changelog.unreleased(text)


class FragmentTest(unittest.TestCase):
    def test_fragments(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp)
            (d / "README.md").write_text("ignored")
            (d / "123.md").write_text("---\nsection: Upgrade notes\n---\n\n- note\n")
            self.assertEqual(changelog.read_fragments(d), [("Upgrade notes", "- note")])
            (d / "bad.md").write_text("- no front matter\n")
            with self.assertRaises(SystemExit):
                changelog.read_fragments(d)


class RevertedTest(unittest.TestCase):
    def test_reverted(self):
        with tempfile.TemporaryDirectory() as tmp:
            def run(*args):
                env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
                return subprocess.run(["git", "-C", tmp, *args], check=True, env=env,
                                      capture_output=True, text=True).stdout.strip()

            run("init", "-q")
            run("commit", "-q", "--allow-empty", "-m", "feat: base (#1)")
            run("commit", "-q", "--allow-empty", "-m", "feat: kept (#2)")
            run("commit", "-q", "--allow-empty", "-m", "feat: reverted (#3)")
            bad = run("rev-parse", "HEAD")
            run("commit", "-q", "--allow-empty", "-m", f"revert: reverted (#4)\n\nThis reverts commit {bad}.")
            revert = run("rev-parse", "HEAD")
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                self.assertEqual(sorted(changelog.reverted("HEAD~3..HEAD")), sorted([revert, bad]))
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
