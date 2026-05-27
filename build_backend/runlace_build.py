from __future__ import annotations

import base64
import hashlib
import io
import tarfile
import time
import zipfile
from pathlib import Path

NAME = "runlace"
VERSION = "0.1.0"
SUMMARY = "Local-first summaries and safety checks for AI agent JSONL traces."
AUTHOR = "mikebfox"
LICENSE = "MIT"
PYTHON_REQUIRES = ">=3.10"
KEYWORDS = "ai-agents,observability,opentelemetry,jsonl,llmops,devtools,privacy"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DIST_INFO = f"{NAME}-{VERSION}.dist-info"


def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_editable(config_settings=None):
    return []


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    wheel_name = f"{NAME}-{VERSION}-py3-none-any.whl"
    wheel_path = Path(wheel_directory) / wheel_name
    records: list[tuple[str, bytes]] = []

    for path in sorted((PROJECT_ROOT / "src" / NAME).glob("*.py")):
        records.append((f"{NAME}/{path.name}", path.read_bytes()))

    records.extend(_metadata_records(metadata_directory))
    _write_wheel(wheel_path, records)
    return wheel_name


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    wheel_name = f"{NAME}-{VERSION}-py3-none-any.whl"
    wheel_path = Path(wheel_directory) / wheel_name
    records = [(f"{NAME}.pth", f"{PROJECT_ROOT / 'src'}\n".encode("utf-8"))]
    records.extend(_metadata_records(metadata_directory))
    _write_wheel(wheel_path, records)
    return wheel_name


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    dist_info = Path(metadata_directory) / DIST_INFO
    dist_info.mkdir(parents=True, exist_ok=True)
    for arcname, content in _dist_info_records():
        (dist_info / Path(arcname).name).write_bytes(content)
    (dist_info / "RECORD").write_text("", encoding="utf-8")
    return DIST_INFO


def prepare_metadata_for_build_editable(metadata_directory, config_settings=None):
    return prepare_metadata_for_build_wheel(metadata_directory, config_settings)


def build_sdist(sdist_directory, config_settings=None):
    base = f"{NAME}-{VERSION}"
    sdist_name = f"{base}.tar.gz"
    target = Path(sdist_directory) / sdist_name
    files = [
        "pyproject.toml",
        "README.md",
        "LICENSE",
        "build_backend/runlace_build.py",
        ".github/workflows/ci.yml",
    ]
    files.extend(str(path.relative_to(PROJECT_ROOT)) for path in sorted((PROJECT_ROOT / "src").rglob("*.py")))
    files.extend(str(path.relative_to(PROJECT_ROOT)) for path in sorted((PROJECT_ROOT / "tests").rglob("*")) if path.is_file())

    with tarfile.open(target, "w:gz") as archive:
        for rel in files:
            data = (PROJECT_ROOT / rel).read_bytes()
            info = tarfile.TarInfo(f"{base}/{rel}")
            info.size = len(data)
            info.mtime = int(time.time())
            archive.addfile(info, io.BytesIO(data))
    return sdist_name


def _metadata_records(metadata_directory) -> list[tuple[str, bytes]]:
    metadata_dir = Path(metadata_directory) if metadata_directory else None
    if metadata_dir and (metadata_dir / DIST_INFO).exists():
        records = []
        for path in sorted((metadata_dir / DIST_INFO).iterdir()):
            if path.is_file() and path.name != "RECORD":
                records.append((f"{DIST_INFO}/{path.name}", path.read_bytes()))
        return records
    return _dist_info_records()


def _dist_info_records() -> list[tuple[str, bytes]]:
    return [
        (f"{DIST_INFO}/METADATA", _metadata().encode("utf-8")),
        (f"{DIST_INFO}/WHEEL", _wheel().encode("utf-8")),
        (f"{DIST_INFO}/entry_points.txt", b"[console_scripts]\nrunlace = runlace.cli:main\n"),
        (f"{DIST_INFO}/top_level.txt", b"runlace\n"),
    ]


def _write_wheel(wheel_path: Path, records: list[tuple[str, bytes]]) -> None:
    record_lines = []
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
        for arcname, content in records:
            wheel.writestr(arcname, content)
            record_lines.append(_record_line(arcname, content))
        record_arcname = f"{DIST_INFO}/RECORD"
        record_lines.append(f"{record_arcname},,")
        wheel.writestr(record_arcname, ("\n".join(record_lines) + "\n").encode("utf-8"))


def _metadata() -> str:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    return (
        "Metadata-Version: 2.3\n"
        f"Name: {NAME}\n"
        f"Version: {VERSION}\n"
        f"Summary: {SUMMARY}\n"
        f"Author: {AUTHOR}\n"
        f"License: {LICENSE}\n"
        f"Requires-Python: {PYTHON_REQUIRES}\n"
        f"Keywords: {KEYWORDS}\n"
        "Project-URL: Homepage, https://github.com/mikebfox/runlace\n"
        "Project-URL: Repository, https://github.com/mikebfox/runlace\n"
        "Project-URL: Issues, https://github.com/mikebfox/runlace/issues\n"
        "Classifier: Development Status :: 3 - Alpha\n"
        "Classifier: Environment :: Console\n"
        "Classifier: Intended Audience :: Developers\n"
        "Classifier: License :: OSI Approved :: MIT License\n"
        "Classifier: Programming Language :: Python :: 3\n"
        "Classifier: Programming Language :: Python :: 3 :: Only\n"
        "Classifier: Programming Language :: Python :: 3.10\n"
        "Classifier: Programming Language :: Python :: 3.11\n"
        "Classifier: Programming Language :: Python :: 3.12\n"
        "Classifier: Programming Language :: Python :: 3.13\n"
        "Classifier: Topic :: Software Development :: Quality Assurance\n"
        "Classifier: Topic :: System :: Monitoring\n"
        "Description-Content-Type: text/markdown\n"
        "\n"
        f"{readme}\n"
    )


def _wheel() -> str:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: runlace-build\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    )


def _record_line(arcname: str, content: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")
    return f"{arcname},sha256={digest},{len(content)}"
