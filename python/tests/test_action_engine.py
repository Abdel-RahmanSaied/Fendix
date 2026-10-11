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
            with self.assertRaises(subprocess.CalledProcessError):
                engine.automatic_tree(self.binary, self.root)
            self.assertEqual(download.call_count, 3)
            self.assertFalse((self.root / "python").exists())

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
            with self.assertRaises(subprocess.CalledProcessError):
                engine.main()
        self.assertEqual(env_file.read_text(), "")
        self.assertEqual(path_file.read_text(), "")
