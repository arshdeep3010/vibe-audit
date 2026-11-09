"""Build the Lambda deployment package: build/lambda.zip.

Installs backend/requirements-lambda.txt as Linux wheels for the Lambda architecture
(works from Windows or macOS too), adds backend/app, and zips it. Both functions (api and
worker) use this one package.

    python infra/build_lambda.py                 # arm64, Python 3.12 (matches Terraform)
    python infra/build_lambda.py --arch x86_64
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
PLATFORMS = {"arm64": "manylinux2014_aarch64", "x86_64": "manylinux2014_x86_64"}
SKIP_DIRS = {"__pycache__", "tests"}
SKIP_SUFFIXES = {".pyc", ".pyo"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--arch", choices=PLATFORMS, default="arm64")
    ap.add_argument("--python", default="3.12")
    args = ap.parse_args()

    stage = BUILD / "lambda"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)

    subprocess.run([
        sys.executable, "-m", "pip", "install", "--quiet", "--no-compile",
        "--target", str(stage),
        "--platform", PLATFORMS[args.arch], "--implementation", "cp",
        "--python-version", args.python, "--only-binary=:all:",
        "-r", str(ROOT / "backend" / "requirements-lambda.txt"),
    ], check=True)
    shutil.copytree(ROOT / "backend" / "app", stage / "app",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    out = BUILD / "lambda.zip"
    out.unlink(missing_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for f in sorted(stage.rglob("*")):
            rel = f.relative_to(stage)
            if f.is_dir() or SKIP_DIRS & set(rel.parts) or f.suffix in SKIP_SUFFIXES:
                continue
            info = zipfile.ZipInfo(rel.as_posix(), date_time=(1980, 1, 1, 0, 0, 0))  # reproducible
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, f.read_bytes())
    print(f"built {out.relative_to(ROOT)} ({out.stat().st_size / 1e6:.1f} MB, {args.arch}, py{args.python})")


if __name__ == "__main__":
    main()
