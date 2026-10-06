from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def _job_block(text: str, name: str, next_name: str | None = None) -> str:
    marker = f"  {name}:\n"
    if marker not in text:
        raise AssertionError(f"Workflow is missing job {name!r}")
    block = text.split(marker, 1)[1]
    if next_name is not None:
        next_marker = f"\n  {next_name}:\n"
        if next_marker not in block:
            raise AssertionError(f"Workflow is missing following job {next_name!r}")
        block = block.split(next_marker, 1)[0]
    return block


class WorkflowSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.update = (ROOT / ".github/workflows/update.yml").read_text(encoding="utf-8")
        cls.checks = (ROOT / ".github/workflows/checks.yml").read_text(encoding="utf-8")
        cls.requirements = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
        cls.npm_package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        cls.npm_lock = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))

    def test_candidate_validation_job_is_read_only_and_checkout_does_not_persist_credentials(self):
        self.assertIn("permissions:\n  contents: read", self.update)
        prepare = _job_block(self.update, "prepare", "publish")
        self.assertIn("permissions:\n      contents: read", prepare)
        self.assertIn("persist-credentials: false", prepare)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", prepare)
        self.assertNotIn("git push", prepare)
        for gate in (
            "node --check sw.js",
            "python -m unittest discover -s tests -v",
            "python scripts/verify_data_snapshot.py --max-age-hours 36",
            "python verify_full_feed.py",
            "python verify_community_ansi_shadow.py --community-only",
        ):
            self.assertIn(gate, prepare)

    def test_only_the_minimal_publish_job_has_write_permission_and_push_token(self):
        publish = _job_block(self.update, "publish", "verify-pages")
        self.assertIn("permissions:\n      contents: write", publish)
        self.assertIn("persist-credentials: false", publish)
        self.assertIn("git push origin HEAD:refs/heads/main", publish)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", publish)
        self.assertNotIn("pip install", publish)
        self.assertNotIn("playwright", publish.lower())
        self.assertNotIn("unittest", publish)
        self.assertIn("git ls-remote origin refs/heads/main", publish)
        self.assertIn("main changed during validation", publish)

    def test_snapshot_commits_use_owner_identity_not_github_actions_bot(self):
        publish = _job_block(self.update, "publish", "verify-pages")
        self.assertIn('git config user.name "iliya-bashrc"', publish)
        self.assertIn('git config user.email "23017098+iliya-bashrc@users.noreply.github.com"', publish)
        self.assertNotIn("github-actions[bot]", publish)
        self.assertNotIn("41898282+github-actions[bot]@users.noreply.github.com", publish)

    def test_public_pages_verification_has_read_only_permissions_and_is_isolated(self):
        pages = _job_block(self.update, "verify-pages")
        self.assertIn("permissions:\n      contents: read", pages)
        self.assertIn("persist-credentials: false", pages)
        self.assertIn("python scripts/verify_pages.py", pages)
        self.assertNotIn("GITHUB_TOKEN", pages)
        self.assertEqual(len(re.findall(r"(?m)^\s+git push\b", self.update)), 1)

    def test_all_actions_are_pinned_and_pull_request_checks_are_read_only(self):
        for workflow in (self.update, self.checks):
            uses = re.findall(r"(?m)^\s+uses:\s+([^\s]+)", workflow)
            self.assertTrue(uses)
            self.assertTrue(all(re.search(r"@[0-9a-f]{40}(?:\s|$)", value) for value in uses), uses)
        self.assertIn("permissions:\n  contents: read", self.checks)
        self.assertIn("persist-credentials: false", self.checks)
        self.assertIn("node --check sw.js", self.checks)
        self.assertIn("node --check sw.js", self.update)
        self.assertNotIn("contents: write", self.checks)

    def test_development_dependencies_are_exact_sha256_locked_in_both_workflows(self):
        package_matches = list(re.finditer(r"(?m)^([A-Za-z0-9_.-]+)==([^\s\\]+)", self.requirements))
        self.assertEqual({match.group(1).lower() for match in package_matches}, {
            "greenlet", "playwright", "pyee", "typing-extensions",
        })
        self.assertEqual(len(package_matches), 4)
        for index, package in enumerate(package_matches):
            end = package_matches[index + 1].start() if index + 1 < len(package_matches) else len(self.requirements)
            block = self.requirements[package.start():end]
            hashes = re.findall(r"(?m)^\s+--hash=sha256:([0-9a-f]{64})\b", block)
            self.assertTrue(hashes, f"{package.group(1)} has no SHA-256 allowlist")
        for workflow in (self.update, self.checks):
            self.assertIn("pip install --require-hashes", workflow)
            self.assertIn("--index-url https://pypi.org/simple", workflow)

    def test_wrangler_and_transitive_npm_packages_are_integrity_locked(self):
        self.assertEqual(self.npm_package["devDependencies"].get("wrangler"), "4.147.0")
        self.assertEqual(self.npm_lock["packages"]["node_modules/wrangler"]["version"], "4.147.0")
        locked_packages = [item for item in self.npm_lock["packages"].values() if item.get("resolved")]
        self.assertGreater(len(locked_packages), 50)
        self.assertTrue(all(re.fullmatch(r"sha512-[A-Za-z0-9+/]+=*", item.get("integrity", ""))
                            for item in locked_packages))
        self.assertIn("npm ci --ignore-scripts --no-audit --no-fund", self.checks)
        self.assertIn("./node_modules/.bin/wrangler deploy --dry-run", self.checks)
        self.assertNotIn("npx --yes wrangler", self.checks)

    def test_snapshot_refresh_is_main_only_and_hands_off_only_validated_snapshot(self):
        self.assertIn("on:\n  schedule:", self.update)
        self.assertIn('cron: "7,37 * * * *"', self.update)
        self.assertIn("group: subzero-static-snapshot-refresh", self.update)
        self.assertIn("cancel-in-progress: false", self.update)
        self.assertIn("workflow_dispatch:", self.update)
        self.assertNotIn("pull_request:", self.update)
        self.assertEqual(self.update.count("if: github.ref == 'refs/heads/main'"), 3)
        self.assertIn("name: validated-snapshot-${{ github.run_id }}-${{ github.run_attempt }}", self.update)
        self.assertIn("if-no-files-found: error", self.update)
        self.assertIn("retention-days: 1", self.update)
        self.assertIn("git add -- snapshot/", self.update)
        publish = _job_block(self.update, "publish", "verify-pages")
        self.assertIn("if git diff --cached --quiet; then", publish)
        self.assertIn('echo "changed=false" >> "$GITHUB_OUTPUT"', publish)
        self.assertIn("if: steps.commit.outputs.changed == 'true'", publish)
        self.assertIn("Only snapshot/ files may be published.", self.update)
        self.assertEqual(self.update.count("contents: write"), 1)


if __name__ == "__main__":
    unittest.main()
