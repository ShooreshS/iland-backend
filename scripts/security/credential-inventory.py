#!/usr/bin/env python3
"""Inventory environment-variable names without executing files or printing values."""

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys


DEFAULT_MAX_FILE_BYTES = 1024 * 1024
MAX_NAMES_BYTES = 1024 * 1024
EXCLUDED_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor",
    "build", "dist", ".next", ".nuxt", ".output", ".gradle", "Pods",
    "tmp", "temp", "coverage", ".cache", "__pycache__", ".venv", "venv",
    "env", ".tox", ".mypy_cache", ".pytest_cache", "target", ".terraform",
    ".aws", ".ssh", ".codex", ".agents",
})
SOURCE_SUFFIXES = frozenset({
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".rb", ".go",
    ".rs", ".sh", ".bash", ".zsh", ".yaml", ".yml", ".toml", ".json",
    ".jsonc", ".ini", ".cfg", ".conf", ".properties", ".xml", ".gradle",
    ".kts", ".java", ".kt", ".php", ".tf", ".hcl",
})
SOURCE_NAMES = frozenset({"Dockerfile", "Containerfile", "Makefile", "Procfile"})
NAME = r"[A-Za-z_][A-Za-z0-9_]*"
VALID_NAME = re.compile(rf"{NAME}\Z", re.ASCII)
DOTENV_ASSIGNMENT = re.compile(rf"^[ \t]*(?:export[ \t]+)?(?P<name>{NAME})[ \t]*=")
REFERENCE_PATTERNS = (
    ("javascript_env", re.compile(rf"\b(?:process|Bun)\.env\.(?P<name>{NAME})\b")),
    ("javascript_env", re.compile(rf"\b(?:process|Bun)\.env\s*\[\s*(['\"])(?P<name>{NAME})\1\s*\]")),
    ("deno_env", re.compile(rf"\bDeno\.env\.get\s*\(\s*(['\"])(?P<name>{NAME})\1\s*\)")),
    ("python_env", re.compile(rf"\bos\.environ\s*\[\s*(['\"])(?P<name>{NAME})\1\s*\]")),
    ("python_env", re.compile(rf"\bos\.(?:environ\.get|getenv)\s*\(\s*(['\"])(?P<name>{NAME})\1(?=\s*[,\)])")),
)


def is_dotenv(path):
    name = path.name
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def relevant_file(path):
    return is_dotenv(path) or path.suffix.lower() in SOURCE_SUFFIXES or path.name in SOURCE_NAMES


def read_regular_file(path, maximum_bytes):
    """Do not follow file symlinks, open devices, or read unbounded input."""
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        return None, "not_regular_file"
    if metadata.st_size > maximum_bytes:
        return None, "file_size_limit"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            return None, "not_regular_file"
        data = source.read(maximum_bytes + 1)
    if len(data) > maximum_bytes:
        return None, "file_size_limit"
    if b"\x00" in data:
        return None, "binary_file"
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "non_utf8_file"


def dotenv_names(content):
    """Extract assignments, skipping the contents of multiline quoted values."""
    quote = None
    for number, line in enumerate(content.splitlines(), 1):
        if quote is not None:
            # Closing quotes may be escaped; never treat multiline value lines
            # that resemble assignments as variable declarations.
            quote = remaining_quote(line, quote)
            continue
        match = DOTENV_ASSIGNMENT.match(line)
        if match:
            yield match.group("name"), number
            value_start = line[match.end():].lstrip()
            if value_start.startswith(("'", '"', "`")):
                quote = remaining_quote(value_start[1:], value_start[0])


def remaining_quote(text, quote):
    escaped = False
    for char in text:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return None
    return quote


def scan(root, maximum_bytes=DEFAULT_MAX_FILE_BYTES):
    records = set()
    skipped = []

    def relative(path):
        try:
            return Path(path).relative_to(root).as_posix()
        except ValueError:
            return "."

    def walk_error(error):
        skipped.append({"file": relative(error.filename or root), "reason": "unreadable_directory"})

    for directory, children, files in os.walk(root, followlinks=False, onerror=walk_error):
        base = Path(directory)
        if len(base.relative_to(root).parts) >= 40:
            children[:] = []
            skipped.append({"file": relative(base), "reason": "directory_depth_limit"})
        else:
            children[:] = sorted(child for child in children
                                 if child not in EXCLUDED_DIRS and not (base / child).is_symlink())
        for filename in sorted(files):
            path = base / filename
            if path.is_symlink() or not relevant_file(path):
                continue
            location = relative(path)
            try:
                content, reason = read_regular_file(path, maximum_bytes)
            except OSError:
                content, reason = None, "unreadable_file"
            if reason:
                skipped.append({"file": location, "reason": reason})
                continue
            if is_dotenv(path):
                for name, number in dotenv_names(content):
                    records.add((name, location, number, "dotenv_assignment"))
            else:
                for source_type, pattern in REFERENCE_PATTERNS:
                    for match in pattern.finditer(content):
                        number = content.count("\n", 0, match.start()) + 1
                        records.add((match.group("name"), location, number, source_type))
    return ([{"name": name, "file": file, "line": line, "source": source}
             for name, file, line, source in sorted(records)],
            sorted(skipped, key=lambda item: (item["file"], item["reason"])))


def load_names(source):
    """Accept names-only arrays. All failures deliberately use one generic error."""
    try:
        if source == "-":
            content = sys.stdin.buffer.read(MAX_NAMES_BYTES + 1)
            if len(content) > MAX_NAMES_BYTES:
                raise ValueError
            content = content.decode("utf-8")
        else:
            content, reason = read_regular_file(Path(source), MAX_NAMES_BYTES)
            if reason:
                raise ValueError
        names = json.loads(content)
        if not isinstance(names, list) or not all(
                isinstance(name, str) and VALID_NAME.fullmatch(name) for name in names):
            raise ValueError
        return sorted(set(names))
    except (OSError, ValueError, TypeError, UnicodeError):
        raise ValueError("names input must be a JSON array of environment variable names only") from None


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only environment variable name inventory; never prints values or executes files.",
        epilog="Static discovery only: names do not establish credential exposure or completed rotation. "
               "Dynamic names, destructuring, shell expansions, external services and excluded files need review.",
    )
    parser.add_argument("--root", required=True, type=Path, help="workspace directory to scan (no symlink root)")
    parser.add_argument("--names-json", metavar="PATH", help="optional names-only JSON array; use - for stdin, never a value map")
    args = parser.parse_args(argv)
    root = args.root.absolute()
    if root.is_symlink() or not root.is_dir():
        parser.error("root must be an accessible directory and must not be a symlink")
    try:
        supplied_names = load_names(args.names_json) if args.names_json else None
    except ValueError as error:
        parser.error(str(error))
    records, skipped = scan(root)
    result = {
        "schema_version": 1,
        "status": "inventory_only",
        "limitations": [
            "Names alone do not establish secret exposure, active credentials, or completed rotation.",
            "Static references can include comments, examples, and unused code; dynamic references can be missed.",
            "Only recognized UTF-8 source/config and dotenv files are scanned; symlinks, dependency/build/cache directories, files over 1 MiB, and directories beyond depth 40 are excluded.",
            "No network or provider queries are performed; historical deployments and external consumers require separate review.",
        ],
        "records": records,
        "skipped": skipped,
    }
    if supplied_names is not None:
        local_names = {record["name"] for record in records}
        provided = set(supplied_names)
        result["comparison"] = {
            "provided_names": supplied_names,
            "provided_names_without_local_reference": sorted(provided - local_names),
            "local_names_not_provided": sorted(local_names - provided),
            "note": "Unmatched names require review; absence from source does not mean unused or safe.",
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
