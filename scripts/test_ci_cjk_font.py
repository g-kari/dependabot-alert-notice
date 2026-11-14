"""Exercise font preparation with dummy APT commands; no network or package install."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERSION = "1:20240730+repack1-1build1"
KEYRING = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
MOCK = r'''
import json, os
from pathlib import Path
import sys

name = Path(sys.argv[0]).name
args = sys.argv[1:]
if name == "sudo":
    if args[0] == "install":
        for directory in args[-2:]:
            Path(directory).mkdir(parents=True, exist_ok=True)
        sys.exit(0)
    os.execvp(args[0], args)
if name in {"apt-get", "apt-cache"}:
    source = next(arg.split("=", 1)[1] for arg in args if arg.startswith("Dir::Etc::sourcelist="))
    record = {"command": name, "args": args, "source_path": source,
              "source": Path(source).read_text()}
    with open(os.environ["MOCK_LOG"], "a") as log:
        log.write(json.dumps(record) + "\n")
scenario = os.environ.get("MOCK_SCENARIO", "")
version = "1:20240730+repack1-1build1"
if name == "apt-get":
    if "update" in args:
        if scenario in {"update-failed", "bad-signature"}:
            print("Fixture: index/authentication failure", file=sys.stderr)
            sys.exit(100)
    elif "--simulate" in args:
        if scenario == "simulation-failed":
            sys.exit(100)
        transactions = {
            "remove": "Remv unrelated [1]\nInst fonts-noto-cjk (" + version + ")",
            "foreign-install": "Inst unrelated (1)\nInst fonts-noto-cjk (" + version + ")",
            "foreign-configure": "Inst fonts-noto-cjk (" + version + ")\nConf unrelated (1)",
            "no-font": "Conf fonts-noto-cjk (" + version + ")",
            "empty-transaction": "",
        }
        print(transactions.get(scenario, "Inst fonts-noto-cjk (" + version + ")\nConf fonts-noto-cjk (" + version + ")"))
    elif scenario in {"install-failed", "bad-checksum"}:
        print("Fixture: package/download integrity failure", file=sys.stderr)
        sys.exit(100)
elif name == "apt-cache":
    if "policy" in args:
        if scenario == "policy-failed":
            sys.exit(100)
        candidates = {"no-candidate": "(none)", "unsafe-candidate": "1;echo-bad", "empty-candidate": ""}
        print("  Candidate: " + candidates.get(scenario, version))
    elif scenario == "madison-failed":
        sys.exit(100)
    elif scenario != "candidate-not-in-index":
        print("fonts-noto-cjk | " + version + " | https://archive.ubuntu.com/ubuntu resolute/main all Packages")
elif name == "dpkg-query":
    print("wrong-version" if scenario == "version-mismatch" else version)
elif name == "fc-match":
    print("DejaVu Sans" if scenario == "missing-glyph-font" else "Noto Sans CJK JP")
'''


class CJKFontTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="devsecops-cjk-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.runner_temp = self.root / "runner temp"
        self.runner_temp.mkdir()
        self.os_release = self.root / "os-release"
        self.os_release.write_text("ID=ubuntu\nVERSION_ID=26.04\nVERSION_CODENAME=resolute\n")
        self.keyring = self.root / "ubuntu-keyring.gpg"
        self.keyring.write_text("dummy keyring, never used by real APT")
        self.log = self.root / "commands.jsonl"
        self.env = {"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.root),
                    "RUNNER_TEMP": str(self.runner_temp), "MOCK_LOG": str(self.log)}
        for name in ["sudo", "apt-get", "apt-cache", "dpkg-query", "fc-match"]:
            path = self.bin / name
            path.write_text(f"#!{sys.executable}\n" + MOCK)
            path.chmod(0o755)
        self.script = self.root / "prepare.sh"
        text = (ROOT / "scripts/prepare_ci_cjk_font.sh").read_text()
        self.script.write_text(text.replace("/etc/os-release", str(self.os_release)).replace(KEYRING, str(self.keyring)))

    def run_script(self, scenario=""):
        self.env["MOCK_SCENARIO"] = scenario
        result = subprocess.run(["bash", str(self.script)], env=self.env,
                                text=True, capture_output=True, timeout=5)
        self.records = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        self.assertEqual(list(self.runner_temp.iterdir()), [], "private APT files must be cleaned")
        return result

    def installs(self):
        return [record for record in self.records if record["command"] == "apt-get"
                and "install" in record["args"] and "--simulate" not in record["args"]]

    def test_fixed_https_source_and_isolated_indexes_for_every_apt_call(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.records), 5)
        for record in self.records:
            self.assertIn(str(self.runner_temp) + "/devsecops-cjk-apt.", record["source_path"])
            self.assertEqual(record["source"],
                             "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu/\n"
                             "Suites: resolute resolute-updates resolute-backports\nComponents: main\n"
                             f"Signed-By: {self.keyring}\n\n"
                             "Types: deb\nURIs: https://security.ubuntu.com/ubuntu/\n"
                             "Suites: resolute-security\nComponents: main\n"
                             f"Signed-By: {self.keyring}\n")
            options = record["args"]
            for option in ["Dir::Etc::sourceparts=-", "APT::Update::Error-Mode=any",
                           "Dir::Cache::pkgcache=", "Dir::Cache::srcpkgcache=",
                           "Acquire::Retries=1", "Acquire::http::Timeout=30", "Acquire::https::Timeout=30",
                           "Acquire::AllowInsecureRepositories=false", "Acquire::AllowDowngradeToInsecureRepositories=false",
                           "APT::Get::AllowUnauthenticated=false", "Acquire::https::Verify-Peer=true",
                           "Acquire::Check-Valid-Until=true", "Acquire::https::Verify-Host=true",
                           "Acquire::https::AllowRedirect=false"]:
                self.assertIn(option, options)
            for prefix, suffix in [("Dir::State::lists=", "/lists"), ("Dir::Cache::archives=", "/archives")]:
                self.assertIn(prefix + str(Path(record["source_path"]).parent) + suffix, options)
        install = self.installs()[0]["args"]
        for option in ["--yes", "--no-install-recommends", "--reinstall", "fonts-noto-cjk=" + VERSION]:
            self.assertIn(option, install)

    def test_runner_sources_and_mirror_lists_are_not_inputs(self):
        # No hostname, priority, or local mirror-file syntax is admitted from the runner.
        source = (ROOT / "scripts/prepare_ci_cjk_font.sh").read_text()
        for ambient_path in ["/etc/apt/sources.list", "/etc/apt/apt-mirrors.txt", "mirror+file:"]:
            self.assertNotIn(ambient_path, source)
        self.assertEqual(self.run_script().returncode, 0)

    def test_wrong_os_fails_before_apt(self):
        for release in ["ID=debian\nVERSION_ID=26.04\nVERSION_CODENAME=resolute\n",
                        "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n",
                        "ID=ubuntu\nVERSION_ID=26.04\nVERSION_CODENAME=other\n"]:
            with self.subTest(release=release):
                self.os_release.write_text(release)
                self.assertNotEqual(self.run_script().returncode, 0)
                self.assertEqual(self.records, [])

    def test_missing_archive_keyring_fails_before_apt(self):
        self.keyring.unlink()
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertEqual(self.records, [])

    def test_metadata_or_signature_failure_stops_before_install(self):
        for scenario in ["update-failed", "bad-signature"]:
            with self.subTest(scenario=scenario):
                self.assertNotEqual(self.run_script(scenario).returncode, 0)
                self.assertEqual(self.installs(), [])
                self.assertEqual(len(self.records), 1)
                self.log.unlink()

    def test_candidate_must_be_safe_and_present_in_private_indexes(self):
        for scenario in ["no-candidate", "unsafe-candidate", "empty-candidate", "candidate-not-in-index",
                         "policy-failed", "madison-failed"]:
            with self.subTest(scenario=scenario):
                self.assertNotEqual(self.run_script(scenario).returncode, 0)
                self.assertEqual(self.installs(), [])
                self.assertEqual(len(self.records), 3 if scenario in {"candidate-not-in-index", "madison-failed"} else 2)
                self.log.unlink()

    def test_transaction_must_only_reinstall_the_font(self):
        for scenario in ["remove", "foreign-install", "foreign-configure", "no-font", "empty-transaction", "simulation-failed"]:
            with self.subTest(scenario=scenario):
                self.assertNotEqual(self.run_script(scenario).returncode, 0)
                self.assertEqual(self.installs(), [])
                self.assertEqual(len(self.records), 4)
                self.log.unlink()

    def test_download_install_or_checksum_failure_is_not_ignored(self):
        for scenario in ["install-failed", "bad-checksum"]:
            with self.subTest(scenario=scenario):
                self.assertNotEqual(self.run_script(scenario).returncode, 0)
                self.assertEqual(len(self.installs()), 1)
                self.log.unlink()

    def test_installed_version_and_glyph_font_are_required(self):
        for scenario in ["version-mismatch", "missing-glyph-font"]:
            with self.subTest(scenario=scenario):
                self.assertNotEqual(self.run_script(scenario).returncode, 0)
                self.log.unlink()

    def test_workflow_runs_contract_before_preparation_and_keeps_timeout(self):
        workflow = (ROOT / ".github/workflows/check.yml").read_text()
        contract = workflow.index("run: python3 scripts/test_ci_cjk_font.py")
        prepare = workflow.index("- name: Prepare official Ubuntu CJK font for browser QA")
        browser = workflow.index("- name: Native console browser acceptance")
        self.assertLess(contract, prepare)
        step = workflow[prepare:browser]
        self.assertIn("timeout-minutes: 3", step)
        self.assertIn("run: bash scripts/prepare_ci_cjk_font.sh", step)
        self.assertNotIn("continue-on-error", step)


if __name__ == "__main__":
    unittest.main()
