"""Owner-only recovery files on POSIX and Windows.

Windows chmod does not restrict a file's DACL. Native Windows security APIs replace
the complete DACL rather than leaving unrelated explicit grants in place. No secret
content is written until these functions return successfully.
"""
from __future__ import annotations

import csv
import ctypes
from ctypes import wintypes
import io
import os
import re
import stat
import subprocess
import threading
from functools import lru_cache
from pathlib import Path


class PrivateFilePermissionError(RuntimeError):
    """Private storage could not be restricted; writing must stop."""


_directory_identities: dict[Path, tuple[int, int]] = {}
_directory_lock = threading.RLock()
_SYSTEM_SID = "S-1-5-18"


def _is_windows() -> bool:
    return os.name == "nt"


def _windows_program(name: str) -> str:
    return str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / name)


def _command(arguments: list[str], *, cwd: Path | None = None) -> bytes:
    try:
        result = subprocess.run(arguments, cwd=cwd, capture_output=True, shell=False,
                                timeout=5, check=False,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PrivateFilePermissionError("Private file permission command is unavailable or timed out") from None
    if result.returncode != 0:
        # Paths and localized tool output can contain sensitive user data.
        raise PrivateFilePermissionError("Private file permission command failed")
    return result.stdout


@lru_cache(maxsize=1)
def _owner_sid() -> str:
    output = _command([_windows_program("whoami.exe"), "/user", "/fo", "csv", "/nh"])
    rows = list(csv.reader(io.StringIO(output.decode("utf-8", errors="replace"))))
    identifiers = [column.strip() for row in rows for column in row
                   if re.fullmatch(r"S-1-(?:[0-9]+-)*[0-9]+", column.strip())]
    if len(identifiers) != 1:
        raise PrivateFilePermissionError("Current Windows account SID could not be established")
    return identifiers[0]


def _checked_path(path: Path, *, directory: bool) -> Path:
    path = Path(path).absolute()
    try:
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise PrivateFilePermissionError("Private storage must not be a symbolic link or junction")
        info = path.stat(follow_symlinks=False)
    except OSError:
        raise PrivateFilePermissionError("Private storage path is unavailable") from None
    if directory != stat.S_ISDIR(info.st_mode) or (not directory and not stat.S_ISREG(info.st_mode)):
        raise PrivateFilePermissionError("Private storage path has an unexpected type")
    return path


@lru_cache(maxsize=1)
def _windows_api():
    try:
        security = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
        kernel = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    except (AttributeError, OSError):
        raise PrivateFilePermissionError("Native Windows file security API is unavailable") from None
    pointer = ctypes.c_void_p
    pointer_to_pointer = ctypes.POINTER(pointer)
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                                                            pointer_to_pointer, ctypes.POINTER(wintypes.ULONG)]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    security.GetSecurityDescriptorDacl.argtypes = [pointer, ctypes.POINTER(wintypes.BOOL), pointer_to_pointer,
                                                  ctypes.POINTER(wintypes.BOOL)]
    security.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    security.GetSecurityDescriptorOwner.argtypes = [pointer, pointer_to_pointer, ctypes.POINTER(wintypes.BOOL)]
    security.GetSecurityDescriptorOwner.restype = wintypes.BOOL
    security.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
                                              pointer, pointer, pointer, pointer]
    security.SetNamedSecurityInfoW.restype = wintypes.DWORD
    security.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                              pointer_to_pointer, pointer_to_pointer, pointer_to_pointer,
                                              pointer_to_pointer, pointer_to_pointer]
    security.GetNamedSecurityInfoW.restype = wintypes.DWORD
    security.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [pointer, wintypes.DWORD,
                                                                            wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR),
                                                                            ctypes.POINTER(wintypes.ULONG)]
    security.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    security.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(wintypes.LPWSTR)]
    security.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [pointer]
    kernel.LocalFree.restype = pointer
    return security, kernel


def _set_windows_acl(path: Path, descriptor_text: str) -> None:
    security, kernel = _windows_api()
    descriptor = ctypes.c_void_p()
    try:
        if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor_text, 1,
                                                                             ctypes.byref(descriptor), None):
            raise PrivateFilePermissionError("Private Windows security descriptor could not be constructed")
        dacl, owner = ctypes.c_void_p(), ctypes.c_void_p()
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        if (not security.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl),
                                                  ctypes.byref(defaulted)) or not present.value or not dacl.value
                or not security.GetSecurityDescriptorOwner(descriptor, ctypes.byref(owner), ctypes.byref(defaulted))
                or not owner.value):
            raise PrivateFilePermissionError("Private Windows security descriptor is incomplete")
        # OWNER | DACL | PROTECTED_DACL: only this explicit path is changed.
        result = security.SetNamedSecurityInfoW(str(path), 1, 0x80000005, owner, None, dacl, None)
        if result:
            raise PrivateFilePermissionError(f"Private Windows permissions could not be set (code {result})")
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)


def _read_windows_acl(path: Path) -> tuple[str, str]:
    security, kernel = _windows_api()
    descriptor, owner = ctypes.c_void_p(), ctypes.c_void_p()
    owner_text, dacl_text = wintypes.LPWSTR(), wintypes.LPWSTR()
    try:
        if security.GetNamedSecurityInfoW(str(path), 1, 5, ctypes.byref(owner), None, None, None,
                                          ctypes.byref(descriptor)):
            raise PrivateFilePermissionError("Private Windows permissions could not be inspected")
        if (not security.ConvertSidToStringSidW(owner, ctypes.byref(owner_text))
                or not security.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 4,
                                                                                      ctypes.byref(dacl_text), None)):
            raise PrivateFilePermissionError("Private Windows permissions could not be verified")
        return owner_text.value, dacl_text.value
    finally:
        for pointer in (owner_text, dacl_text, descriptor):
            if pointer:
                kernel.LocalFree(ctypes.cast(pointer, ctypes.c_void_p))


def _private_dacl(dacl: str, owner_sid: str, *, directory: bool) -> bool:
    prefix = re.match(r"D:([A-Z]*)(?=\()", dacl)
    if not prefix or "P" not in prefix.group(1):
        return False
    entries = re.findall(r"\(([^()]*)\)", dacl)
    if len(entries) != len({owner_sid, _SYSTEM_SID}) or prefix.end() + sum(len(entry) + 2 for entry in entries) != len(dacl):
        return False
    identities: set[str] = set()
    for entry in entries:
        parts = entry.split(";")
        if (len(parts) != 6 or parts[0] != "A" or parts[2].lower() not in {"fa", "0x1f01ff", "0x001f01ff"}
                or parts[3] or parts[4]):
            return False
        if parts[1] != ("OICI" if directory else ""):
            return False
        identities.add(_SYSTEM_SID if parts[5] == "SY" else parts[5])
    return identities == {owner_sid, _SYSTEM_SID}


def _windows_permissions(path: Path, *, directory: bool) -> None:
    owner_sid = _owner_sid()
    flags = "OICI" if directory else ""
    dacl = f"D:P(A;{flags};FA;;;{owner_sid})"
    if owner_sid != _SYSTEM_SID:
        dacl += f"(A;{flags};FA;;;SY)"
    _set_windows_acl(path, f"O:{owner_sid}{dacl}")
    actual_owner, actual_dacl = _read_windows_acl(path)
    if actual_owner != owner_sid or not _private_dacl(actual_dacl, owner_sid, directory=directory):
        raise PrivateFilePermissionError("Private storage ACL remains accessible to an unexpected account")


def secure_directory(path: Path) -> None:
    """Create/restrict a directory to owner and Windows SYSTEM; cache identity."""
    try:
        Path(path).mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        raise PrivateFilePermissionError("Private directory could not be created") from None
    path = _checked_path(path, directory=True)
    with _directory_lock:
        info = path.stat(follow_symlinks=False)
        identity = (info.st_dev, info.st_ino)
        if _directory_identities.get(path) == identity:
            return
        if _is_windows():
            _windows_permissions(path, directory=True)
        else:
            try:
                path.chmod(0o700)
            except OSError:
                raise PrivateFilePermissionError("Private directory permissions could not be secured") from None
            if stat.S_IMODE(path.stat().st_mode) != 0o700:
                raise PrivateFilePermissionError("Private directory permissions could not be verified")
        _directory_identities[path] = identity


def secure_file(path: Path) -> None:
    """Restrict an existing empty temporary file before writing secret content."""
    path = _checked_path(path, directory=False)
    if _is_windows():
        _windows_permissions(path, directory=False)
    else:
        try:
            path.chmod(0o600)
        except OSError:
            raise PrivateFilePermissionError("Private file permissions could not be secured") from None
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise PrivateFilePermissionError("Private file permissions could not be verified")
