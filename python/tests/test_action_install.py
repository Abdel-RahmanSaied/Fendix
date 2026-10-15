"""Verified installation for the composite Action.

scripts/action/install.sh resolves one exact release, runs the installer
bundled with the Action revision (scripts/install.sh) with the signature
REQUIRED in an environment the Action controls, checks the exact version at a
private path, and only then publishes that path. These tests run both scripts
for real with no network: a stub curl serves a fake release, a stub cosign
passes or fails, and one event log records the order of every download,
signature check and binary execution.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest

import yaml

REPO = Path(__file__).resolve().parents[2]
INSTALLER = REPO / "scripts" / "install.sh"
WRAPPER = REPO / "scripts" / "action" / "install.sh"
OFFICIAL = "Fendix-app/Fendix"
SYSTEM_PATH = "/usr/bin:/bin"
OS_NAME = platform.system().lower()
ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[platform.machine().lower()]
CURRENT_SIGNER = "https://github.com/Fendix-app/Fendix/.github/workflows/release.yml@refs/tags/"
# Releases through v3.4.1 were signed before the repository transfer; the
# installer keeps that signer for them. Read it from the installer itself.
HISTORICAL_REPO = re.search(r'^HISTORICAL_SIGN_REPO="([^"]+)"$', INSTALLER.read_text(), re.M).group(1)
HISTORICAL_SIGNER = f"https://github.com/{HISTORICAL_REPO}/.github/workflows/release.yml@refs/tags/"

CURL = """#!/bin/sh
# Stub curl: serve a file per URL from $SERVE_DIR, or fail like curl -f.
out=""; url=""; prev=""
for arg in "$@"; do
  [ "$prev" = "-o" ] && out="$arg"
  prev="$arg"; url="$arg"
done
echo "curl $url" >> "$EVENTS"
file="$SERVE_DIR/$(printf '%s' "$url" | sed 's#[^A-Za-z0-9._-]#_#g')"
[ -f "$file" ] || exit 22
if [ -n "$out" ]; then cp "$file" "$out"; else cat "$file"; fi
"""

COSIGN = """#!/bin/sh
# Stub cosign: record the identity it was asked to verify.
identity=""; prev=""
for arg in "$@"; do
  [ "$prev" = "--certificate-identity" ] && identity="$arg"
  prev="$arg"
done
echo "cosign $1 $identity" >> "$EVENTS"
exit "${COSIGN_EXIT:-0}"
"""


def served_name(url):
    return re.sub(r"[^A-Za-z0-9._-]", "_", url)


class InstallFixture(unittest.TestCase):
    """A fake release server, stub tools and an ordered event log."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.serve = self.root / "serve"
        self.serve.mkdir()
        self.events = self.root / "events"
        self.events.write_text("")
        self.tools = self.root / "tools"
        self.tools.mkdir()
        (self.tools / "curl").write_text(CURL)
        (self.tools / "curl").chmod(0o755)
        self.cosign_dir = self.root / "cosign"
        self.cosign_dir.mkdir()
        (self.cosign_dir / "cosign").write_text(COSIGN)
        (self.cosign_dir / "cosign").chmod(0o755)
        self.runner_temp = self.root / "runner temp"
        self.runner_temp.mkdir()
        self.github_path = self.root / "github_path"
        self.github_path.write_text("")

    def publish(self, version, *, reported=None, repo=OFFICIAL, signed=True, checksum_ok=True):
        """Serve a release of the fake binary, which logs every execution."""
        name = f"fendix-{version}-{OS_NAME}-{ARCH}"
        url = f"https://github.com/{repo}/releases/download/{version}/{name}"
        binary = textwrap.dedent(f"""\
            #!/bin/sh
            echo "exec fendix $*" >> "$EVENTS"
            echo "fendix version {reported or version} ({OS_NAME}/{ARCH})"
        """).encode()
        (self.serve / served_name(url)).write_bytes(binary)
        digest = hashlib.sha256(binary).hexdigest() if checksum_ok else "0" * 64
        (self.serve / served_name(url + ".sha256")).write_text(f"{digest}  {name}\n")
        if signed:
            (self.serve / served_name(url + ".sig")).write_text("signature")
            (self.serve / served_name(url + ".crt")).write_text("certificate")

    def latest(self, tag):
        url = f"https://api.github.com/repos/{OFFICIAL}/releases/latest"
        (self.serve / served_name(url)).write_text(json.dumps({"tag_name": tag, "name": tag}, indent=2))

    def env(self, cosign=True, **extra):
        path = [str(self.tools)] + ([str(self.cosign_dir)] if cosign else []) + [SYSTEM_PATH]
        env = {"PATH": ":".join(path), "HOME": str(self.root), "EVENTS": str(self.events), "SERVE_DIR": str(self.serve)}
        env.update(extra)
        return env

    def log(self):
        return self.events.read_text().splitlines()

    def first(self, prefix):
        return next((i for i, line in enumerate(self.log()) if line.startswith(prefix)), None)

    def requires_absent_system_cosign(self):
        if shutil.which("cosign", path=SYSTEM_PATH):
            self.skipTest("a cosign binary exists on the system PATH, so 'no cosign' cannot be simulated")


class BundledInstallerContractTests(InstallFixture):
    """The behaviour of scripts/install.sh that the Action relies on."""

    def install(self, version, cosign=True, **extra):
        target = self.root / "bin"
        target.mkdir(exist_ok=True)
        env = self.env(cosign, FENDIX_VERSION=version, FENDIX_DIR=str(target), FENDIX_REQUIRE_SIGNATURE="1", **extra)
        env["PATH"] = f"{target}:{env['PATH']}"
        result = subprocess.run(["sh", str(INSTALLER)], env=env, capture_output=True, text=True)
        return result, target / "fendix"

    def test_required_signature_without_cosign_is_refused(self):
        self.requires_absent_system_cosign()
        self.publish("v3.6.1")
        result, binary = self.install("v3.6.1", cosign=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FENDIX_REQUIRE_SIGNATURE=1 but cosign is not installed", result.stderr)
        self.assertFalse(binary.exists())
        self.assertIsNone(self.first("exec fendix"))

    def test_signature_failure_is_refused(self):
        self.publish("v3.6.1")
        result, binary = self.install("v3.6.1", COSIGN_EXIT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cosign signature verification FAILED", result.stderr)
        self.assertFalse(binary.exists())
        self.assertIsNone(self.first("exec fendix"))

    def test_missing_signature_assets_are_refused(self):
        self.publish("v3.6.1", signed=False)
        result, binary = self.install("v3.6.1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no .sig/.crt", result.stderr)
        self.assertFalse(binary.exists())

    def test_checksum_mismatch_is_refused_before_any_signature_check(self):
        self.publish("v3.6.1", checksum_ok=False)
        result, binary = self.install("v3.6.1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Checksum mismatch", result.stderr)
        self.assertFalse(binary.exists())
        self.assertIsNone(self.first("cosign"))

    def test_verified_release_is_installed_and_runs_only_after_verification(self):
        self.publish("v3.6.1")
        result, binary = self.install("v3.6.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(binary.exists())
        verified, executed = self.first("cosign verify-blob"), self.first("exec fendix")
        self.assertIsNotNone(verified)
        self.assertIsNotNone(executed)
        self.assertLess(verified, executed)

    def test_signer_identity_is_historical_for_v3_4_1_and_current_for_v3_6(self):
        self.assertNotEqual(HISTORICAL_REPO, OFFICIAL)
        for version, signer in (("v3.4.1", HISTORICAL_SIGNER), ("v3.6.0", CURRENT_SIGNER), ("v3.6.1", CURRENT_SIGNER)):
            with self.subTest(version=version):
                self.events.write_text("")
                self.publish(version)
                result, _ = self.install(version)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"cosign verify-blob {signer}{version}", self.log())


class ActionHarness(InstallFixture):
    """Runs scripts/action/install.sh the way action.yml does."""

    def run_action(self, version, cosign=True, action_path=REPO, **inherited):
        env = self.env(cosign, VERSION=version, ACTION_PATH=str(action_path), RUNNER_TEMP=str(self.runner_temp),
                       GITHUB_PATH=str(self.github_path), **inherited)
        return subprocess.run(["bash", str(WRAPPER)], env=env, capture_output=True, text=True)

    def private_dirs(self):
        return sorted(p for p in self.runner_temp.iterdir() if p.name.startswith("fendix-bin."))

    def published(self):
        return [line for line in self.github_path.read_text().splitlines() if line]

    def assertInstalled(self, result, version):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        published = self.published()
        self.assertEqual(len(published), 1)
        directory = Path(published[0])
        self.assertEqual(directory.parent, self.runner_temp)
        self.assertTrue(directory.name.startswith("fendix-bin."))
        self.assertIn(f"Verified Fendix {version} at {directory}/fendix", result.stdout)
        return directory

    def assertNothingPublished(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.published(), [])
        self.assertEqual(self.private_dirs(), [], "a failed install left its private directory behind")


class ActionInstallTests(ActionHarness):
    """scripts/action/install.sh: what the Action itself guarantees."""

    def test_exact_version_installs_into_a_private_directory(self):
        self.publish("v3.6.1")
        directory = self.assertInstalled(self.run_action("v3.6.1"), "v3.6.1")
        self.assertTrue((directory / "fendix").exists())
        self.assertIn(f"curl https://github.com/{OFFICIAL}/releases/download/v3.6.1/fendix-v3.6.1-{OS_NAME}-{ARCH}", self.log())

    def test_each_install_gets_its_own_directory(self):
        self.publish("v3.6.1")
        first = self.assertInstalled(self.run_action("v3.6.1"), "v3.6.1")
        self.github_path.write_text("")
        second = self.assertInstalled(self.run_action("v3.6.1"), "v3.6.1")
        self.assertNotEqual(first, second)

    def test_prerelease_tags_are_exact_versions(self):
        for tag in ("v3.5.0-rc.2", "v1.2.0-rc1"):
            with self.subTest(tag=tag):
                self.github_path.write_text("")
                self.publish(tag)
                self.assertInstalled(self.run_action(tag), tag)

    def test_v3_6_1_never_accepts_v3_6_10(self):
        self.publish("v3.6.1", reported="v3.6.10")
        result = self.run_action("v3.6.1")
        self.assertNothingPublished(result)
        self.assertIn("requested Fendix v3.6.1 but the installed binary reports 'fendix version v3.6.10", result.stdout)

    def test_latest_is_resolved_once_to_an_exact_tag(self):
        self.latest("v3.6.1")
        self.publish("v3.6.1")
        result = self.run_action("latest")
        self.assertInstalled(result, "v3.6.1")
        self.assertIn("latest resolved to v3.6.1", result.stdout)
        api = [line for line in self.log() if "api.github.com" in line]
        self.assertEqual(api, [f"curl https://api.github.com/repos/{OFFICIAL}/releases/latest"])

    def test_latest_that_does_not_name_a_release_fails_closed(self):
        for tag in ("v1", "fendix-app-v3.4.1", "", "main"):
            with self.subTest(tag=tag):
                self.events.write_text("")
                self.latest(tag)
                result = self.run_action("latest")
                self.assertNothingPublished(result)
                self.assertIsNone(self.first("curl https://github.com/"))

    def test_unresolvable_latest_fails_closed(self):
        result = self.run_action("latest")
        self.assertNothingPublished(result)
        self.assertIn("could not resolve 'latest'", result.stdout)

    def test_invalid_version_input_fails_before_any_download(self):
        for version in ("3.6.1", "v3.6", "v1", "main", "v3.6.1;id", "v3.6.1 ", "../v3.6.1"):
            with self.subTest(version=version):
                self.events.write_text("")
                result = self.run_action(version)
                self.assertNothingPublished(result)
                self.assertEqual(self.log(), [])

    def test_nothing_is_published_when_verification_fails(self):
        self.publish("v3.6.1")
        result = self.run_action("v3.6.1", COSIGN_EXIT="1")
        self.assertNothingPublished(result)
        self.assertIsNone(self.first("exec fendix"))

    def test_no_cosign_means_no_install(self):
        self.requires_absent_system_cosign()
        self.publish("v3.6.1")
        result = self.run_action("v3.6.1", cosign=False)
        self.assertNothingPublished(result)
        self.assertIn("cosign is not installed", result.stderr)
        self.assertIsNone(self.first("exec fendix"))

    def test_the_installer_bundled_with_the_action_is_the_one_that_runs(self):
        bundled = self.root / "action"
        (bundled / "scripts").mkdir(parents=True)
        text = INSTALLER.read_text().replace("# Main\n", '# Main\necho "bundled installer marker"\n', 1)
        (bundled / "scripts" / "install.sh").write_text(text)
        self.publish("v3.6.1")
        result = self.run_action("v3.6.1", action_path=bundled)
        self.assertInstalled(result, "v3.6.1")
        self.assertIn("bundled installer marker", result.stdout)
        self.assertFalse(any("get.fendix.dev" in line for line in self.log()))


class InheritedEnvironmentTests(ActionHarness):
    """No inherited FENDIX_* variable can redirect or weaken the Action."""

    HOSTILE = {
        "FENDIX_REPO": "attacker/fendix",
        "FENDIX_SIGN_REPO": "attacker/fendix",
        "FENDIX_ALLOW_UNVERIFIED": "1",
        "FENDIX_REQUIRE_SIGNATURE": "0",
        "FENDIX_VERSION": "v0.0.1",
        "FENDIX_SHA256": "f" * 64,
    }

    def setUp(self):
        super().setUp()
        self.elsewhere = self.root / "elsewhere"
        self.publish("v3.6.1")
        # A decoy release under the attacker repository and version.
        self.publish("v0.0.1", repo="attacker/fendix")
        self.publish("v3.6.1", repo="attacker/fendix")

    def test_hostile_variables_change_nothing(self):
        result = self.run_action("v3.6.1", FENDIX_DIR=str(self.elsewhere), **self.HOSTILE)
        directory = self.assertInstalled(result, "v3.6.1")
        downloads = [line for line in self.log() if line.startswith("curl ")]
        self.assertTrue(downloads)
        self.assertTrue(all(f"/{OFFICIAL}/releases/download/v3.6.1/" in line for line in downloads), downloads)
        self.assertIn(f"cosign verify-blob {CURRENT_SIGNER}v3.6.1", self.log())
        self.assertFalse(self.elsewhere.exists())
        self.assertTrue((directory / "fendix").exists())

    def test_each_variable_alone_cannot_redirect_the_install(self):
        for name, value in dict(self.HOSTILE, FENDIX_DIR=str(self.elsewhere)).items():
            with self.subTest(variable=name):
                self.events.write_text("")
                self.github_path.write_text("")
                result = self.run_action("v3.6.1", **{name: value})
                self.assertInstalled(result, "v3.6.1")
                self.assertNotIn("attacker", self.events.read_text())
                self.assertFalse(self.elsewhere.exists())

    def test_inherited_variables_cannot_weaken_verification(self):
        for cosign_exit, cosign in (("1", True), ("0", False)):
            with self.subTest(cosign="fails" if cosign else "absent"):
                if not cosign:
                    self.requires_absent_system_cosign()
                self.events.write_text("")
                result = self.run_action("v3.6.1", cosign=cosign, COSIGN_EXIT=cosign_exit, **self.HOSTILE)
                self.assertNothingPublished(result)
                self.assertIsNone(self.first("exec fendix"))


class ActionWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        action = yaml.safe_load((REPO / "action.yml").read_text())
        cls.steps = action["runs"]["steps"]
        cls.names = [step.get("name") for step in cls.steps]

    def test_cosign_is_installed_for_every_caller_before_fendix(self):
        cosign = self.names.index("Install source verification tool")
        install = self.names.index("Install Fendix")
        self.assertLess(cosign, install)
        self.assertNotIn("if", self.steps[cosign])
        self.assertLess(self.names.index("Validate managed inputs"), cosign)
        self.assertLess(install, self.names.index("Set up Python"))

    def test_install_runs_the_wrapper_without_interpolating_inputs(self):
        step = self.steps[self.names.index("Install Fendix")]
        self.assertEqual(step["run"].strip(), 'bash "$ACTION_PATH/scripts/action/install.sh"')
        self.assertEqual(step["env"]["ACTION_PATH"], "${{ github.action_path }}")
        self.assertEqual(step["env"]["VERSION"], "${{ inputs.version }}")

    def test_the_action_never_fetches_the_live_installer(self):
        self.assertNotIn("get.fendix.dev", (REPO / "action.yml").read_text())
        self.assertNotIn("get.fendix.dev", WRAPPER.read_text())


if __name__ == "__main__":
    unittest.main()
