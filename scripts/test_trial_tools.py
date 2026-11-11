#!/usr/bin/env python3
"""Trial packaging tests; use synthetic environment values and a fake binary."""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TRIAL = ROOT / "packaging" / "trial"


class TrialToolsTests(unittest.TestCase):
    def test_failed_job_retries_keep_the_producer_artifact_and_attempt(self):
        workflow = (ROOT / ".github/workflows/trial.yml").read_text()
        reference = "${{ needs.build.outputs.artifact_name }}"
        self.assertIn('echo "artifact_name=candidate-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"', workflow)
        self.assertIn('artifact_name: ${{ steps.source.outputs.artifact_name }}', workflow)
        self.assertIn('build_attempt: ${{ steps.source.outputs.build_attempt }}', workflow)
        for job in ("mac-smoke", "windows-smoke", "ready"):
            section = re.search(r"(?ms)^  " + re.escape(job) + r":\n(.*?)(?=^  [a-z][a-z-]*:\n|\Z)", workflow).group(1)
            self.assertIn("name: " + reference, section)
            self.assertNotIn("name: candidate-", section)
        self.assertIn("'build_run_attempt': os.environ['GITHUB_RUN_ATTEMPT']", workflow)
        self.assertIn("'verification_run_attempt': os.environ['GITHUB_RUN_ATTEMPT']", workflow)
        self.assertIn("manifest['build_run_attempt'] == os.environ['BUILD_RUN_ATTEMPT']", workflow)
        self.assertIn("manifest['candidate_artifact'] == os.environ['CANDIDATE_ARTIFACT']", workflow)
        # Mock GitHub's successful-build outputs surviving failed-jobs retries.
        # No workflow, executable, network, or GitHub mutation is run here.
        for producer_attempt, verification_attempt in ((1, 1), (1, 2), (1, 3), (2, 3)):
            outputs = {"artifact_name": f"candidate-42-{producer_attempt}",
                       "build_attempt": str(producer_attempt)}
            artifact_store = {outputs["artifact_name"]: b"same-immutable-candidate"}
            for job in ("mac-smoke", "windows-smoke", "ready"):
                resolved_name = outputs["artifact_name"]
                self.assertEqual(artifact_store[resolved_name], b"same-immutable-candidate", job)
            manifest = {"build_run_attempt": outputs["build_attempt"],
                        "verification_run_attempt": str(verification_attempt)}
            self.assertEqual(manifest["build_run_attempt"], str(producer_attempt))
            self.assertEqual(manifest["verification_run_attempt"], str(verification_attempt))
            if verification_attempt != producer_attempt:
                self.assertNotIn(f"candidate-42-{verification_attempt}", artifact_store)

    def test_config_is_empty_local_and_offline(self):
        text = (TRIAL / "trial-config.yaml").read_text()
        for line in (
            "targets: []", "  host: 127.0.0.1", "  port: 18999",
            "disable_approval: true", "  auto_eval: false", "  feeds: []",
            "gh_path: ./disabled-gh", "claude_path: ./disabled-claude",
            "codex_path: ./disabled-codex", "    container_path: ./disabled-container",
        ):
            self.assertIn(line, text.splitlines())
        self.assertRegex(text, r"rss:\n  enabled: false\n")
        self.assertRegex(text, r"threat:\n  enabled: false\n")
        self.assertNotIn("https://", text)

    def test_windows_launcher_has_an_allowlisted_child_environment(self):
        text = (TRIAL / "Trial.ps1").read_text()
        self.assertIn("$info.EnvironmentVariables.Clear()", text)
        self.assertIn("$info.UseShellExecute = $false", text)
        self.assertIn("$info.WorkingDirectory = $trial", text)
        self.assertIn("[Guid]::NewGuid()", text)
        self.assertIn("--auto-update=false", text)
        for name in ("GH_TOKEN", "GITHUB_TOKEN", "SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "DISCORD_WEBHOOK_URL", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            self.assertNotIn("EnvironmentVariables['" + name + "']", text)
        self.assertNotIn("ExecutionPolicy", text)

    @unittest.skipIf(os.name == "nt", "Unix launcher needs Bash")
    def test_unix_launcher_clears_credentials_and_separates_home_and_data(self):
        with tempfile.TemporaryDirectory(prefix="trial-tools-") as raw:
            root = pathlib.Path(raw)
            package = root / "package with spaces"
            package.mkdir()
            for item in TRIAL.iterdir():
                shutil.copyfile(item, package / item.name)
            binary = package / "dependabot-alert-notice"
            binary.write_text('''#!/bin/bash
set -euo pipefail
test -z "${GH_TOKEN:-}${GITHUB_TOKEN:-}${SLACK_BOT_TOKEN:-}${SLACK_APP_TOKEN:-}${DISCORD_WEBHOOK_URL:-}${OPENAI_API_KEY:-}${ANTHROPIC_API_KEY:-}"
test "$PATH" = "$HOME/bin"
test "$GH_CONFIG_DIR" = "$HOME/gh"
test "$CODEX_HOME" = "$HOME/codex"
test "$SECURITY_NOTICE_AUTO_UPDATE" = 0
test ! -f "$HOME/original-home-marker"
test "$1" = --config
test "$2" = "$PWD/config.yaml"
test "$3" = --auto-update=false
printf '%s\\n' "$PWD" > "$HOME/capture"
case "${4:-}" in
  --version) printf 'dependabot-alert-notice fixture\\n' ;;
  --web-url) printf 'http://127.0.0.1:18999\\n' ;;
  *) exit 8 ;;
esac
''')
            binary.chmod(0o755)
            old_home = root / "old home"
            old_home.mkdir()
            (old_home / "original-home-marker").write_text("keep")
            temp = root / "temporary"
            temp.mkdir()
            environment = dict(os.environ, HOME=str(old_home), TMPDIR=str(temp),
                               GH_TOKEN="synthetic-only", GITHUB_TOKEN="synthetic-only",
                               SLACK_BOT_TOKEN="synthetic-only", SLACK_APP_TOKEN="synthetic-only",
                               DISCORD_WEBHOOK_URL="synthetic-only", OPENAI_API_KEY="synthetic-only",
                               ANTHROPIC_API_KEY="synthetic-only")
            for mode, expected in (([], "dependabot-alert-notice fixture"),
                                   (["--web-url"], "http://127.0.0.1:18999")):
                result = subprocess.run(["bash", str(package / "Trial.sh"), *mode],
                                        env=environment, text=True, capture_output=True, check=True)
                self.assertEqual(result.stdout.strip(), expected)
            directories = list(temp.glob("devsecops-trial.*"))
            self.assertEqual(len(directories), 2)
            for directory in directories:
                self.assertEqual((directory / "home/capture").read_text().strip(), str(directory))
                self.assertEqual((directory / "config.yaml").read_bytes(), (TRIAL / "trial-config.yaml").read_bytes())
                self.assertFalse((directory / "store.db").exists())
            self.assertEqual((old_home / "original-home-marker").read_text(), "keep")
            rejected = subprocess.run(["bash", str(package / "Trial.sh"), "--update"],
                                      env=environment, capture_output=True)
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(len(list(temp.glob("devsecops-trial.*"))), 2)


if __name__ == "__main__":
    unittest.main()
