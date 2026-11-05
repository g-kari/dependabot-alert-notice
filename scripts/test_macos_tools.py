"""Mock macOS/gh/launchd commands; no real credentials, services or network."""
import hashlib
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]

class MacToolsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="security-notice-tools-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.package = self.root / "package with spaces"
        self.package.mkdir()
        self.home = self.root / "home"
        self.home.mkdir()
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                        HOME=str(self.home), SECURITY_NOTICE_INSTALL_DIR=str(self.root / "install"),
                        SECURITY_NOTICE_DATA_DIR=str(self.root / "data"), MOCK_ROOT=str(self.root), SECURITY_NOTICE_AUTO_UPDATE="0")
        for key in ["GH_TOKEN", "GITHUB_TOKEN", "CODEX_HOME", "SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "DISCORD_WEBHOOK_URL", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"]:
            self.env.pop(key, None)
        self.command("uname", 'if [ "$1" = -s ]; then echo Darwin; else echo arm64; fi')
        self.command("id", 'if [ "$1" = -un ]; then echo fixture; else echo 501; fi')
        self.command("sw_vers", "echo 26.3")
        self.command("stat", 'if [ "$2" = %u ]; then echo 501; else echo 600; fi')
        self.command("sudo", 'exec "$@"')
        self.launchctl = self.command("launchctl", '''case "$1" in
print) test -f "$MOCK_ROOT/loaded" ;;
bootstrap) touch "$MOCK_ROOT/loaded" ;;
bootout) rm -f "$MOCK_ROOT/loaded" ;;
*) exit 1 ;;
esac''')
        self.plutil = self.command("plutil", 'exec python3 -c "import plistlib,sys; plistlib.load(open(sys.argv[1],\'rb\'))" "$2"')
        self.install = self.command("install", 'prev=""; last=""; for arg in "$@"; do prev="$last"; last="$arg"; done; cp "$prev" "$last"')
        self.daemons = self.root / "LaunchDaemons"
        self.daemons.mkdir()

    def command(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/bash\nset -eu\n" + body + "\n")
        path.chmod(0o755)
        return path

    def script(self, relative, name=None):
        src = (ROOT / relative).read_text()
        src = src.replace("/bin/launchctl", str(self.launchctl)).replace("/usr/bin/plutil", str(self.plutil)).replace("/usr/bin/install", str(self.install)).replace("/Library/LaunchDaemons", str(self.daemons))
        src = src.replace('export PATH="/opt/homebrew/bin:', 'export PATH="'+str(self.bin)+':/opt/homebrew/bin:')
        path = self.package / (name or Path(relative).name)
        path.write_text(src)
        return path

    def run_script(self, path, *args):
        return subprocess.run(["bash", str(path), *args], env=self.env, text=True, capture_output=True, timeout=10)

    def test_service_install_has_user_boundary_and_preserves_secrets(self):
        install_dir = Path(self.env["SECURITY_NOTICE_INSTALL_DIR"])
        current = install_dir / "current"
        current.mkdir(parents=True)
        (current / "Service.command").write_text("fixture")
        script = self.script("packaging/macos/service-macos.sh")
        self.env["SLACK_BOT_TOKEN"] = "test-only-secret"
        self.env["GH_TOKEN"] = "test-only-github-secret"
        result = self.run_script(script, "install")
        self.assertEqual(result.returncode, 0, result.stderr)
        plist = next(self.daemons.iterdir())
        data = plistlib.loads(plist.read_bytes())
        self.assertEqual(data["ProgramArguments"][:3], [str(self.launchctl), "asuser", "501"])
        self.assertIn("fixture", data["ProgramArguments"])
        self.assertIn("SECURITY_NOTICE_DATA_DIR="+self.env["SECURITY_NOTICE_DATA_DIR"],data["ProgramArguments"])
        self.assertTrue(data["RunAtLoad"])
        self.assertTrue(data["KeepAlive"])
        self.assertNotIn("test-only-secret", plist.read_text()+result.stdout+result.stderr)
        self.assertNotIn("test-only-github-secret", plist.read_text()+result.stdout+result.stderr)
        env_file=Path(self.env["SECURITY_NOTICE_DATA_DIR"])/"service.env.sh"
        self.assertEqual(env_file.stat().st_mode & 0o777,0o600)
        self.assertIn("GH_TOKEN",env_file.read_text())
        original=env_file.read_bytes()
        self.assertEqual(self.run_script(script,"install").returncode,0)
        self.assertEqual(env_file.read_bytes(),original)
        self.assertEqual(self.run_script(script,"stop").returncode,0)
        self.assertFalse((self.root/"loaded").exists())
        self.assertEqual(self.run_script(script,"start").returncode,0)
        self.assertTrue((self.root/"loaded").exists())
        self.assertEqual(self.run_script(script,"uninstall").returncode,0)
        self.assertEqual(env_file.read_bytes(),original)

    def test_service_install_rejects_unsafe_existing_env(self):
        current=Path(self.env["SECURITY_NOTICE_INSTALL_DIR"])/"current"
        current.mkdir(parents=True);(current/"Service.command").write_text("fixture")
        data=Path(self.env["SECURITY_NOTICE_DATA_DIR"]);data.mkdir()
        target=self.root/"other";target.write_text("export FIXTURE=private\n")
        (data/"service.env.sh").symlink_to(target)
        script=self.script("packaging/macos/service-macos.sh")
        result=self.run_script(script,"install")
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.root/"loaded").exists())
        self.assertEqual(target.read_text(),"export FIXTURE=private\n")

    def test_build_uses_only_two_application_dockerfiles(self):
        for name in ["Dockerfile.apple-claude","Dockerfile.apple-codex"]:
            shutil.copyfile(ROOT/name,self.package/name)
        (self.package/"auth.json").write_text("do not send")
        self.command("container", '''if [ "$1" = build ]; then
context=""; for arg in "$@"; do context="$arg"; done
exec python3 -c 'import os,sys; assert sorted(os.listdir(sys.argv[1]))==["Dockerfile.apple-claude","Dockerfile.apple-codex"]' "$context"
fi''')
        result=self.run_script(self.script("packaging/macos/Build.command"))
        self.assertEqual(result.returncode,0,result.stderr)

    def test_update_restores_service_on_download_failure(self):
        (self.daemons/"xyz.0g0.security-notice.plist").write_text("fixture")
        (self.root/"loaded").touch()
        (self.package/"service-macos.sh").write_text('#!/bin/bash\nprintf "%s\\n" "$1" >> "$MOCK_ROOT/actions"\n')
        (self.package/"Setup.command").write_text("#!/bin/bash\nexit 9\n")
        script=self.script("packaging/macos/Update.command")
        result=self.run_script(script)
        self.assertEqual(result.returncode,9,result.stderr)
        self.assertEqual((self.root/"actions").read_text(),"stop\nstart\n")

    def test_service_runner_uses_env_and_exec_without_browser(self):
        self.command("container", "exit 0")
        script=self.script("packaging/macos/Service.command")
        data=Path(self.env["SECURITY_NOTICE_DATA_DIR"]);data.mkdir()
        (data/"service.env.sh").write_text("export FIXTURE_SECRET=fixture-value\n")
        (data/"service.env.sh").chmod(0o600)
        (self.package/"config.yaml.example").write_text("targets: []\n")
        fake=self.package/"dependabot-alert-notice"
        fake.write_text('#!/bin/bash\ntest "$FIXTURE_SECRET" = fixture-value\nprintf "%s" "$PWD" > "$MOCK_ROOT/ran"\n')
        fake.chmod(0o755)
        # Service.command intentionally replaces PATH; inject fixture command paths.
        src=script.read_text().replace('export PATH="/opt/homebrew/bin:/usr/local/bin:${HOME}/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin"','export PATH="'+str(self.bin)+':$PATH"')
        script.write_text(src)
        result=self.run_script(script)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.root/"ran").read_text(),str(data))
        self.assertNotIn("fixture-value",result.stdout+result.stderr)

    def test_installer_verifies_and_preserves_data_for_both_architectures(self):
        for cpu,arch in [("arm64","arm64"),("x86_64","amd64")]:
            with self.subTest(arch=arch):
                self.command("uname",f'if [ "$1" = -s ]; then echo Darwin; else echo {cpu}; fi')
                tag="v0.3.0";folder=f"security-notice_{tag}_macos_{arch}";asset=f"{folder}.zip"
                archive=self.root/asset
                with zipfile.ZipFile(archive,"w") as z:
                    for source,name in [("packaging/macos/Start.command","Start.command"),("packaging/macos/config.yaml.example","config.yaml.example"),("packaging/macos/MAC-START.md","MAC-START.md"),("packaging/macos/Service.command","Service.command"),("packaging/macos/Update.command","Update.command")]:
                        z.writestr(folder+"/"+name,(ROOT/source).read_text())
                    z.writestr(folder+"/dependabot-alert-notice",f"#!/bin/bash\necho 'dependabot-alert-notice {tag}'\n")
                    z.writestr(folder+"/../outside","do not extract")
                checksum=self.root/"macos-checksums.txt"
                checksum.write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+"  "+asset+"\n")
                self.env.update(MOCK_ASSET=asset)
                self.command("gh",'''case "$1" in
auth) exit 0 ;;
api) echo v0.3.0 ;;
release) dest=""; for arg in "$@"; do dest="$arg"; done; cp "$MOCK_ROOT/$MOCK_ASSET" "$MOCK_ROOT/macos-checksums.txt" "$dest/" ;;
*) exit 1 ;;
esac''')
                script=self.script("scripts/setup-macos.sh","Setup.command")
                data=Path(self.env["SECURITY_NOTICE_DATA_DIR"]);data.mkdir(exist_ok=True);(data/"store.db").write_text("existing-data")
                result=self.run_script(script)
                self.assertEqual(result.returncode,0,result.stderr)
                install=Path(self.env["SECURITY_NOTICE_INSTALL_DIR"])
                self.assertEqual(os.readlink(install/"current"),folder)
                self.assertFalse((install/"outside").exists())
                self.assertFalse((install/".install-lock").exists())
                self.assertEqual((data/"store.db").read_text(),"existing-data")
                before=os.readlink(install/"current")
                checksum.write_text("0"*64+"  "+asset+"\n")
                failed=self.run_script(script)
                self.assertNotEqual(failed.returncode,0)
                self.assertEqual(os.readlink(install/"current"),before)
                self.assertFalse((install/".install-lock").exists())

if __name__ == "__main__":
    unittest.main()
