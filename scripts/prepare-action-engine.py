#!/usr/bin/env python3
"""Prepare the Action's Python tree outside the scanned checkout.

The automatic path uses a signed build record to bind the installed binary to
an immutable source commit. An explicit engine_path remains caller-managed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

REPO = "Fendix-app/Fendix"
ISSUER = "https://token.actions.githubusercontent.com"


def safe_line(value):
    if "\n" in value or "\r" in value:
        raise ValueError("Action paths must not contain line breaks")
    return value


def validate_record(record, version, binary):
    if record.get("schema_version") != "engine-build-record/v1":
        raise ValueError("unsupported engine build record schema")
    source = record.get("source", {})
    if record.get("engine_version") != version or source.get("tag") != version:
        raise ValueError("build record version does not match installed binary")
    if source.get("repository") != REPO:
        raise ValueError("build record belongs to another repository")
    commit = source.get("commit", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("build record has no immutable source commit")
    digest = "sha256:" + hashlib.sha256(binary.read_bytes()).hexdigest()
    if not any(a.get("executable_sha256") == digest for a in record.get("artifacts", [])):
        raise ValueError("installed binary is not an artifact in the signed build record")
    return commit


def download(url, path):
    with urllib.request.urlopen(url, timeout=120) as response:
        with path.open("wb") as target:
            while chunk := response.read(1024 * 1024):
                target.write(chunk)


def extract_python(archive, destination):
    """Extract regular python/ files only, never links or traversal paths."""
    with tarfile.open(archive, "r:gz") as source:
        for member in source.getmembers():
            parts = Path(member.name).parts
            if len(parts) < 3 or parts[1] != "python":
                continue
            relative = Path(*parts[2:])
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("unsafe source archive path")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("source archive contains a link or special file")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as stream:
                target.write_bytes(stream.read())
    validate_tree(destination)


def validate_tree(tree):
    if not (tree / "engine.py").is_file() or not (tree / "requirements.txt").is_file():
        raise ValueError("engine_path must contain engine.py and requirements.txt")


def automatic_tree(binary, work):
    output = subprocess.check_output([str(binary), "version"], text=True).strip()
    match = re.fullmatch(r"fendix version (v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?) \([^\n]+\)", output)
    if not match:
        raise ValueError("automatic Python preparation requires a released binary; provide engine_path for custom builds")
    version = match.group(1)
    base = f"https://github.com/{REPO}/releases/download/{version}"
    for name in ("build-record.json", "build-record.json.sig", "build-record.json.crt"):
        download(f"{base}/{name}", work / name)
    subprocess.run([
        "cosign", "verify-blob", "--signature", str(work / "build-record.json.sig"),
        "--certificate", str(work / "build-record.json.crt"),
        "--certificate-identity", f"https://github.com/{REPO}/.github/workflows/release.yml@refs/tags/{version}",
        "--certificate-oidc-issuer", ISSUER, str(work / "build-record.json"),
    ], check=True)
    commit = validate_record(json.loads((work / "build-record.json").read_text()), version, binary)
    archive = work / "source.tar.gz"
    download(f"https://codeload.github.com/{REPO}/tar.gz/{commit}", archive)
    tree = work / "python"
    tree.mkdir()
    extract_python(archive, tree)
    print(f"Prepared Python source for {version} at commit {commit}")
    return tree


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine-path", default=os.environ.get("ENGINE_PATH", ""))
    args = parser.parse_args()
    import shutil
    binary = shutil.which("fendix")
    if not binary:
        raise ValueError("install Fendix before preparing its Python engine")
    runner_temp = Path(safe_line(os.environ["RUNNER_TEMP"])).resolve()
    work = Path(tempfile.mkdtemp(prefix="fendix-action-", dir=runner_temp))
    if args.engine_path:
        tree = Path(safe_line(args.engine_path)).resolve()
        validate_tree(tree)
    else:
        tree = automatic_tree(Path(binary).resolve(), work)
    venv = work / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    subprocess.run([str(venv / "bin/python"), "-m", "pip", "install", "--disable-pip-version-check", "-r", str(tree / "requirements.txt")], check=True)
    # Publish only after dependency installation and sync both succeed.
    subprocess.run([str(binary), "engine", "sync", "--dir", str(tree)], check=True)
    with open(os.environ["GITHUB_ENV"], "a") as handle:
        handle.write(f"FENDIX_ENGINE={safe_line(str(tree))}\n")
    with open(os.environ["GITHUB_PATH"], "a") as handle:
        handle.write(f"{safe_line(str(venv / 'bin'))}\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"::error::Python engine preparation failed: {error}", file=sys.stderr)
        sys.exit(1)
