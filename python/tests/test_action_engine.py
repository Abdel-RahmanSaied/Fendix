"""Fail-closed source/binary binding and safe extraction for the composite Action."""
import copy
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import subprocess
import os

spec = importlib.util.spec_from_file_location("action_engine", Path(__file__).resolve().parents[2] / "scripts/prepare-action-engine.py")
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


class ActionEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "fendix"
        self.binary.write_bytes(b"release binary")
        self.record = {"schema_version": "engine-build-record/v1", "engine_version": "v3.6.0", "source": {"tag": "v3.6.0", "repository": engine.REPO, "commit": "a" * 40}, "artifacts": [{"executable_sha256": "sha256:" + hashlib.sha256(self.binary.read_bytes()).hexdigest()}]}

    def test_record_binds_installed_binary_to_commit(self):
        self.assertEqual(engine.validate_record(self.record, "v3.6.0", self.binary), "a" * 40)

    def test_refuses_mismatched_records(self):
        for path, bad in [("schema_version", "unknown"), ("engine_version", "v3.5.0"), ("source.tag", "main"), ("source.repository", "attacker/repo"), ("source.commit", "main"), ("artifacts", [])]:
            with self.subTest(path=path):
                record = copy.deepcopy(self.record)
                obj = record
                keys = path.split(".")
                for key in keys[:-1]:
                    obj = obj[key]
                obj[keys[-1]] = bad
                with self.assertRaises(ValueError):
                    engine.validate_record(record, "v3.6.0", self.binary)

    def test_refuses_another_binary(self):
        self.binary.write_bytes(b"another executable")
        with self.assertRaises(ValueError):
            engine.validate_record(self.record, "v3.6.0", self.binary)

    def archive(self, members):
        archive = self.root / "source.tar.gz"
        with tarfile.open(archive, "w:gz") as handle:
            for name, kind in members:
                member = tarfile.TarInfo(name)
                if kind == "symlink":
                    member.type = tarfile.SYMTYPE
                    member.linkname = "/etc/passwd"
                    handle.addfile(member)
                else:
                    member.size = 1
                    handle.addfile(member, io.BytesIO(b"x"))
        return archive

    def test_extracts_only_python_tree(self):
        archive = self.archive([("repo/python/engine.py", "file"), ("repo/python/requirements.txt", "file"), ("repo/scripts/install.sh", "file")])
        target = self.root / "python"
        engine.extract_python(archive, target)
        self.assertTrue((target / "engine.py").is_file())
        self.assertFalse((target / "scripts").exists())

    def test_refuses_traversal_and_links(self):
        for name, kind in [("repo/python/../../escape", "file"), ("repo/python/engine.py", "symlink")]:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    engine.extract_python(self.archive([(name, kind)]), self.root / "extract")

    def test_explicit_tree_must_include_requirements(self):
        tree = self.root / "explicit"
        tree.mkdir()
        (tree / "engine.py").touch()
        with self.assertRaises(ValueError):
            engine.validate_tree(tree)
        (tree / "requirements.txt").touch()
        engine.validate_tree(tree)

    def test_rejects_github_environment_injection(self):
        for value in ["/tmp/tree\nKEY=value", "/tmp/tree\rKEY=value"]:
            with self.assertRaises(ValueError):
                engine.safe_line(value)

    def test_signature_failure_never_fetches_source(self):
        with mock.patch.object(engine.subprocess, "check_output", return_value="fendix version v3.6.0 (linux/amd64)"), mock.patch.object(engine, "download") as download, mock.patch.object(engine.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "cosign")):
            with self.assertRaises(engine.PrepareError) as failure:
                engine.automatic_tree(self.binary, self.root)
            self.assertEqual(download.call_count, 3)
            self.assertFalse((self.root / "python").exists())
        message = str(failure.exception)
        self.assertIn("signed build record for Fendix v3.6.0 did not verify", message)
        self.assertIn("release.yml@refs/tags/v3.6.0", message)
        self.assertIn("exit 1", message)

    def test_failed_install_publishes_no_runner_environment(self):
        tree = self.root / "engine"
        tree.mkdir()
        (tree / "engine.py").touch()
        (tree / "requirements.txt").touch()
        env_file, path_file = self.root / "env", self.root / "path"
        env_file.touch()
        path_file.touch()
        def run(command, **kwargs):
            if "pip" in command:
                raise subprocess.CalledProcessError(1, command)
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.root), "GITHUB_ENV": str(env_file), "GITHUB_PATH": str(path_file)}), mock.patch("sys.argv", ["prepare", "--engine-path", str(tree)]), mock.patch("shutil.which", return_value=str(self.binary)), mock.patch.object(engine.subprocess, "run", side_effect=run):
            with self.assertRaises(engine.PrepareError) as failure:
                engine.main()
        self.assertEqual(env_file.read_text(), "")
        self.assertEqual(path_file.read_text(), "")
        self.assertIn("installing the Python engine's dependencies failed", str(failure.exception))
        self.assertIn("exit 1", str(failure.exception))


def make_tree(root, name, lock=False):
    tree = root / name
    tree.mkdir()
    (tree / "engine.py").touch()
    (tree / "requirements.txt").write_text("semgrep>=1.45.0\n")
    if lock:
        (tree / "requirements.lock").write_text("semgrep==1.141.0 \\\n    --hash=sha256:" + "0" * 64 + "\n")
    return tree


class DependencyPlanTests(unittest.TestCase):
    """Which dependency set is installed, by who owns the Python tree."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_legacy_release_without_lock_gets_the_pydantic_bound(self):
        for version in ("v3.5.0", "v3.5.1", "v3.6.0"):
            with self.subTest(version=version):
                tree = make_tree(self.root, version)
                args, note = engine.install_plan(tree, version)
                self.assertEqual(args, ["-r", str(tree / "requirements.txt"), "pydantic<2.14"])
                self.assertIn(f"Fendix {version} ships no requirements.lock", note)

    def test_release_tree_with_lock_installs_only_the_lock_with_hashes(self):
        tree = make_tree(self.root, "release", lock=True)
        args, note = engine.install_plan(tree, "v3.6.1")
        self.assertEqual(args, ["--require-hashes", "-r", str(tree / "requirements.lock")])
        self.assertNotIn("pydantic<2.14", args)
        self.assertIn("Installing the locked dependencies of Fendix v3.6.1", note)

    def test_v3_6_1_does_not_get_the_bound_even_on_a_prerelease(self):
        tree = make_tree(self.root, "rc", lock=True)
        args, _ = engine.install_plan(tree, "v3.6.1-rc.1")
        self.assertNotIn("pydantic<2.14", args)

    def test_release_after_v3_6_0_without_lock_fails_closed(self):
        tree = make_tree(self.root, "lockless")
        with self.assertRaises(engine.PrepareError) as failure:
            engine.install_plan(tree, "v3.6.1")
        self.assertIn("has no python/requirements.lock", str(failure.exception))

    def test_custom_engine_path_is_unchanged_even_when_it_has_a_lock(self):
        tree = make_tree(self.root, "custom", lock=True)
        args, note = engine.install_plan(tree, None)
        self.assertEqual(args, ["-r", str(tree / "requirements.txt"), "pydantic<2.14"])
        self.assertIn("Custom engine_path", note)

    def run_main(self, tree, version, engine_path):
        env_file, path_file = self.root / "env", self.root / "path"
        env_file.write_text("")
        path_file.write_text("")
        calls = []
        argv = ["prepare"] + (["--engine-path", str(tree)] if engine_path else [])
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.root), "GITHUB_ENV": str(env_file), "GITHUB_PATH": str(path_file)}), \
                mock.patch("sys.argv", argv), mock.patch("shutil.which", return_value="/usr/bin/fendix"), \
                mock.patch.object(engine, "automatic_tree", return_value=(tree, version)), \
                mock.patch.object(engine.subprocess, "run", side_effect=lambda command, **kw: calls.append(command)):
            engine.main()
        pip = [c for c in calls if "pip" in c]
        self.assertEqual(len(pip), 1)
        return pip[0], env_file.read_text()

    def test_main_installs_the_release_lock(self):
        tree = make_tree(self.root, "release", lock=True)
        pip, published = self.run_main(tree, "v3.6.1", engine_path=False)
        self.assertEqual(pip[-3:], ["--require-hashes", "-r", str(tree / "requirements.lock")])
        self.assertNotIn("pydantic<2.14", pip)
        self.assertIn(f"FENDIX_ENGINE={tree}", published)

    def test_main_keeps_the_custom_engine_path_install(self):
        tree = make_tree(self.root, "custom", lock=True)
        pip, _ = self.run_main(tree, None, engine_path=True)
        self.assertEqual(pip[-3:], ["-r", str(tree / "requirements.txt"), "pydantic<2.14"])


class FakeResponse(io.BytesIO):
    pass


def http_error(code, reason):
    return engine.urllib.error.HTTPError("https://example.invalid/x", code, reason, None, None)


class DownloadTests(unittest.TestCase):
    """Only transient failures are retried, boundedly, keeping the reason."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        sleep = mock.patch.object(engine.time, "sleep")
        self.sleep = sleep.start()
        self.addCleanup(sleep.stop)

    def download(self, effects):
        target = self.root / "file"
        with mock.patch.object(engine.urllib.request, "urlopen", side_effect=effects) as urlopen:
            try:
                engine.download("https://example.invalid/file", target)
                return target, urlopen.call_count, None
            except engine.PrepareError as error:
                return target, urlopen.call_count, error

    def test_transient_failure_retries_and_recovers(self):
        for transient in (http_error(503, "Service Unavailable"), TimeoutError("timed out"), ConnectionResetError("reset by peer")):
            with self.subTest(error=type(transient).__name__):
                self.sleep.reset_mock()
                target, calls, error = self.download([transient, FakeResponse(b"payload")])
                self.assertIsNone(error)
                self.assertEqual(calls, 2)
                self.assertEqual(target.read_bytes(), b"payload")
                self.assertEqual(self.sleep.call_count, 1)

    def test_retries_are_bounded_and_keep_the_original_reason(self):
        _, calls, error = self.download([TimeoutError("timed out")] * 5)
        self.assertEqual(calls, engine.DOWNLOAD_ATTEMPTS)
        self.assertIn("timed out", str(error))
        self.assertIn(f"after {engine.DOWNLOAD_ATTEMPTS} attempts", str(error))
        self.assertIn("https://example.invalid/file", str(error))

    def test_permanent_failures_are_not_retried(self):
        import ssl
        for permanent in (http_error(404, "Not Found"), http_error(403, "Forbidden"),
                          engine.urllib.error.URLError(ssl.SSLCertVerificationError("certificate verify failed"))):
            with self.subTest(error=str(permanent)):
                _, calls, error = self.download([permanent, FakeResponse(b"never")])
                self.assertEqual(calls, 1)
                self.assertIsNotNone(error)
        self.sleep.assert_not_called()


class BuildRecordTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.binary = self.root / "fendix"
        self.binary.write_bytes(b"release binary")

    def missing_record(self, version):
        with mock.patch.object(engine.subprocess, "check_output", return_value=f"fendix version {version} (linux/amd64)"), \
                mock.patch.object(engine.urllib.request, "urlopen", side_effect=http_error(404, "Not Found")) as urlopen, \
                mock.patch.object(engine.time, "sleep") as sleep, mock.patch.object(engine.subprocess, "run") as run:
            with self.assertRaises(engine.PrepareError) as failure:
                engine.automatic_tree(self.binary, self.root)
        self.assertEqual(urlopen.call_count, 1)
        sleep.assert_not_called()
        run.assert_not_called()
        return str(failure.exception)

    def test_release_before_build_records_is_explained_and_not_retried(self):
        message = self.missing_record("v3.4.1")
        self.assertIn("Fendix v3.4.1 predates signed build records", message)
        self.assertIn("v3.5.0", message)
        self.assertIn("engine_path", message)
        self.assertNotIn("HTTP Error 404", message)

    def test_recent_release_without_a_record_says_so(self):
        message = self.missing_record("v3.6.1")
        self.assertIn("Fendix v3.6.1 has no signed build record", message)
        self.assertIn("still be uploading", message)


class FailureMessageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def failing_main(self, failing):
        tree = make_tree(self.root, "custom")
        env_file, path_file = self.root / "env", self.root / "path"
        env_file.write_text("")
        path_file.write_text("")
        def run(command, **kwargs):
            if failing(command):
                raise subprocess.CalledProcessError(3, command)
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.root), "GITHUB_ENV": str(env_file), "GITHUB_PATH": str(path_file)}), \
                mock.patch("sys.argv", ["prepare", "--engine-path", str(tree)]), mock.patch("shutil.which", return_value="/usr/bin/fendix"), \
                mock.patch.object(engine.subprocess, "run", side_effect=run):
            with self.assertRaises(engine.PrepareError) as failure:
                engine.main()
        self.assertEqual(env_file.read_text(), "")
        return str(failure.exception), tree

    def test_pip_failure_names_the_dependency_set(self):
        message, tree = self.failing_main(lambda command: "pip" in command)
        self.assertIn("installing the Python engine's dependencies failed", message)
        self.assertIn("requirements.txt", message)
        self.assertIn("exit 3", message)
        self.assertIn("see the output above", message)

    def test_engine_sync_failure_is_explicit(self):
        message, tree = self.failing_main(lambda command: "sync" in command)
        self.assertIn(f"fendix engine sync --dir {tree.resolve()} failed", message)
        self.assertIn("exit 3", message)

    def test_reported_error_is_one_workflow_command_line(self):
        line = engine.error_line(engine.PrepareError("first\nsecond %"))
        self.assertTrue(line.startswith("::error::Python engine preparation failed: "))
        self.assertNotIn("\n", line)
        self.assertIn("first%0Asecond %25", line)
