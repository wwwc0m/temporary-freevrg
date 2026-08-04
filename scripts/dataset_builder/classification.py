from __future__ import annotations

from pathlib import PurePosixPath
from typing import Iterable


LIB_MODULES = {
    "bsnmp",
    "bzip2",
    "cap_net",
    "expat",
    "geli",
    "iconv",
    "ldns",
    "lib9p",
    "libarchive",
    "libc",
    "libcasper",
    "libfetch",
    "libradius",
    "openssl",
    "pam_krb5",
    "pam_login_access",
    "posix_spawnp",
    "stdio",
    "zlib",
}

TOOL_MODULES = {
    "bhyve",
    "bhyveload",
    "blocklistd",
    "bootpd",
    "bsdinstall",
    "bsdpatch",
    "bsnmpd",
    "bspatch",
    "dhclient",
    "etcupdate",
    "fetch",
    "ftpd",
    "ggatec",
    "openssh",
    "ping",
    "portsnap",
    "routed",
    "rpcbind",
    "rtsold",
    "ssh",
    "telnet",
    "telnetd",
    "xz",
}


def classify_scope(module: str, changed_paths: Iterable[str] = ()) -> str:
    """Classify by changed build paths first, then by an audited module fallback."""
    paths = [PurePosixPath(path) for path in changed_paths]
    code_paths = [path for path in paths if not _is_documentation_path(path)]
    if code_paths:
        roots = {path.parts[0] for path in code_paths if path.parts}
        if roots == {"sys"}:
            return "kernel"
        if any(_is_library_path(path) for path in code_paths):
            if not any(_is_tool_path(path) for path in code_paths):
                return "lib"
        if any(_is_tool_path(path) for path in code_paths):
            return "tool"

    normalized = module.lower()
    if normalized == "igmp":
        return "other"
    if normalized in LIB_MODULES:
        return "lib"
    if normalized in TOOL_MODULES:
        return "tool"
    return "kernel"


def is_document_only_commit(message: str, changed_paths: Iterable[str]) -> bool:
    if message.strip().lower().startswith("document r"):
        return True
    paths = [PurePosixPath(path) for path in changed_paths]
    return bool(paths) and all(_is_documentation_path(path) for path in paths)


def grade_commit(changed_paths: Iterable[str], module_path: str | None = None) -> str:
    """Provide a deterministic initial grade; v1.4 audited grades override this."""
    paths = [path for path in changed_paths if not _is_documentation_path(PurePosixPath(path))]
    if not paths:
        return "noise_only"
    if len(paths) <= 20:
        return "focused"
    if module_path:
        concentrated = sum(path.startswith(module_path.rstrip("/") + "/") for path in paths)
        ratio = concentrated / len(paths)
        if ratio >= 0.8:
            return "large_concentrated" if len(paths) > 80 else "medium"
    roots = {PurePosixPath(path).parts[0] for path in paths if PurePosixPath(path).parts}
    return "bundled_multi_module" if len(roots) > 2 else "medium"


def _is_documentation_path(path: PurePosixPath) -> bool:
    text = path.as_posix().lower()
    if text in {"updating", "readme", "news", "changes"}:
        return True
    if text.startswith(("release/doc/", "documentation/", "docs/")):
        return True
    return "/man/" in f"/{text}" or "/relnotes/" in f"/{text}"


def _is_library_path(path: PurePosixPath) -> bool:
    text = path.as_posix()
    return text.startswith("lib/") or text.startswith("crypto/") or "/lib/" in f"/{text}"


def _is_tool_path(path: PurePosixPath) -> bool:
    return path.parts[:1] in {("bin",), ("sbin",), ("usr.bin",), ("usr.sbin",)}
