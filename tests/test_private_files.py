import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.security import private_files


SID = "S-1-5-21-111-222-333-444"


@pytest.fixture
def windows_acl(monkeypatch):
    calls: list[tuple] = []
    applied: dict[str, tuple[str, str]] = {}
    private_files._owner_sid.cache_clear()
    private_files._directory_identities.clear()
    monkeypatch.setattr(private_files, "_is_windows", lambda: True)

    def command(arguments: list[str], *, cwd: Path | None = None) -> bytes:
        calls.append(("command", arguments, cwd))
        if Path(arguments[0]).name == "whoami.exe":
            return f'"fixture-user","{SID}"\r\n'.encode()
        raise AssertionError("Only bounded owner SID discovery uses a subprocess")

    def set_acl(path: Path, descriptor: str) -> None:
        calls.append(("set_acl", path, descriptor))
        assert descriptor.startswith(f"O:{SID}D:P")
        applied[str(path)] = (SID, descriptor[len(f"O:{SID}"):])

    def read_acl(path: Path) -> tuple[str, str]:
        calls.append(("read_acl", path))
        return applied[str(path)]

    monkeypatch.setattr(private_files, "_command", command)
    monkeypatch.setattr(private_files, "_set_windows_acl", set_acl)
    monkeypatch.setattr(private_files, "_read_windows_acl", read_acl)
    yield calls, applied
    private_files._owner_sid.cache_clear()
    private_files._directory_identities.clear()


def test_windows_replaces_complete_acl_with_owner_and_system_only(tmp_path, windows_acl) -> None:
    target = tmp_path / "empty.tmp"
    target.touch()
    private_files.secure_file(target)
    calls, applied = windows_acl
    assert applied[str(target)] == (SID, f"D:P(A;;FA;;;{SID})(A;;FA;;;SY)")
    assert any(call[0] == "set_acl" and call[1] == target for call in calls)
    assert any(call[0] == "read_acl" and call[1] == target for call in calls)
    assert all(call[0] != "command" or Path(call[1][0]).name == "whoami.exe" for call in calls)


def test_windows_directory_acl_inherits_only_owner_system_and_is_cached(tmp_path, windows_acl) -> None:
    directory = tmp_path / "recovery"
    private_files.secure_directory(directory)
    calls, applied = windows_acl
    count = len(calls)
    private_files.secure_directory(directory)
    assert len(calls) == count
    assert applied[str(directory)] == (SID, f"D:P(A;OICI;FA;;;{SID})(A;OICI;FA;;;SY)")


def test_windows_file_acl_is_inspected_for_every_new_temporary_write(tmp_path, windows_acl) -> None:
    target = tmp_path / "empty.tmp"
    target.touch()
    private_files.secure_file(target)
    private_files.secure_file(target)
    calls, _ = windows_acl
    assert sum(call[0] == "read_acl" for call in calls) == 2
    assert sum(call[0] == "command" for call in calls) == 1


def test_windows_acl_verification_rejects_extra_explicit_account(tmp_path, windows_acl, monkeypatch) -> None:
    target = tmp_path / "empty.tmp"
    target.touch()
    read_acl = private_files._read_windows_acl

    def changed(path: Path) -> tuple[str, str]:
        owner, dacl = read_acl(path)
        return owner, dacl + "(A;;FA;;;WD)"

    monkeypatch.setattr(private_files, "_read_windows_acl", changed)
    with pytest.raises(private_files.PrivateFilePermissionError, match="unexpected account"):
        private_files.secure_file(target)


@pytest.mark.skipif(os.name != "nt", reason="SDDL abbreviation resolution uses native Windows APIs")
def test_windows_dacl_verification_resolves_sddl_sid_abbreviations() -> None:
    owner = private_files._sid_text("LA")
    assert owner.startswith("S-1-5-21-")
    assert private_files._private_dacl("D:P(A;;FA;;;LA)(A;;FA;;;SY)", owner, directory=False)
    assert private_files._private_dacl("D:P(A;OICI;FA;;;LA)(A;OICI;FA;;;SY)", owner, directory=True)
    assert not private_files._private_dacl("D:P(A;OICI;FA;;;LA)(A;OICI;FA;;;LS)", owner, directory=True)


@pytest.mark.skipif(os.name != "nt", reason="SDDL abbreviation resolution uses native Windows APIs")
def test_windows_dacl_verification_rejects_abbreviated_extra_accounts() -> None:
    owner = private_files._sid_text("LA")
    for abbreviation in ("BA", "BU", "WD", "OW", "AU", "AN"):
        dacl = f"D:P(A;;FA;;;LA)(A;;FA;;;{abbreviation})"
        assert not private_files._private_dacl(dacl, owner, directory=False)
        assert not private_files._private_dacl(dacl, private_files._SYSTEM_SID, directory=False)


def test_windows_accepts_token_owner_administrators_ownership(tmp_path, windows_acl, monkeypatch) -> None:
    target = tmp_path / "empty.tmp"
    target.touch()
    read_acl = private_files._read_windows_acl

    def administrators_owned(path: Path) -> tuple[str, str]:
        return "S-1-5-32-544", read_acl(path)[1]

    monkeypatch.setattr(private_files, "_read_windows_acl", administrators_owned)
    monkeypatch.setattr(private_files, "_token_owner_sid", lambda: "S-1-5-32-544")
    private_files.secure_file(target)


def test_windows_rejects_foreign_owner_without_token_owner_support(tmp_path, windows_acl, monkeypatch) -> None:
    target = tmp_path / "empty.tmp"
    target.touch()
    read_acl = private_files._read_windows_acl

    def administrators_owned(path: Path) -> tuple[str, str]:
        return "S-1-5-32-544", read_acl(path)[1]

    monkeypatch.setattr(private_files, "_read_windows_acl", administrators_owned)
    monkeypatch.setattr(private_files, "_token_owner_sid", lambda: None)
    with pytest.raises(private_files.PrivateFilePermissionError, match="not the current account"):
        private_files.secure_file(target)


def test_failed_acl_does_not_cache_directory_success(tmp_path, windows_acl, monkeypatch) -> None:
    directory = tmp_path / "recovery"
    def unavailable(path: Path, descriptor: str) -> None:
        raise private_files.PrivateFilePermissionError("mock failure")

    monkeypatch.setattr(private_files, "_set_windows_acl", unavailable)
    with pytest.raises(private_files.PrivateFilePermissionError):
        private_files.secure_directory(directory)
    assert directory not in private_files._directory_identities


def test_permission_commands_are_bounded_no_shell_and_do_not_expose_output(monkeypatch) -> None:
    seen = []

    def failed(arguments, **kwargs):
        seen.append((arguments, kwargs))
        return SimpleNamespace(returncode=5, stdout=b"UNTRUSTED_STDOUT", stderr=b"UNTRUSTED_STDERR")

    monkeypatch.setattr(private_files.subprocess, "run", failed)
    with pytest.raises(private_files.PrivateFilePermissionError) as captured:
        private_files._command(["icacls.exe", "empty.tmp", "/verify"])
    assert "UNTRUSTED" not in str(captured.value)
    assert seen[0][1]["timeout"] == 5
    assert seen[0][1]["shell"] is False
    assert seen[0][1]["capture_output"] is True


def test_permission_command_timeout_fails_closed(monkeypatch) -> None:
    def timeout(arguments, **kwargs):
        raise subprocess.TimeoutExpired(arguments, 5, output=b"UNTRUSTED_OUTPUT")

    monkeypatch.setattr(private_files.subprocess, "run", timeout)
    with pytest.raises(private_files.PrivateFilePermissionError) as captured:
        private_files._command(["icacls.exe", "empty.tmp"])
    assert "UNTRUSTED" not in str(captured.value)


def test_recovery_atomic_write_never_serializes_before_permission_success(tmp_path, monkeypatch) -> None:
    from app.inbound import manager

    monkeypatch.setattr(manager, "secure_directory", lambda path: None)

    def rejected(path):
        raise private_files.PrivateFilePermissionError("mock ACL rejected")

    monkeypatch.setattr(manager, "secure_file", rejected)
    dumped = []
    monkeypatch.setattr(manager.json, "dump", lambda *args, **kwargs: dumped.append(args))
    with pytest.raises(private_files.PrivateFilePermissionError):
        manager._private_json(tmp_path / "source-snapshot.json", {"payload": "never-written"})
    assert dumped == []
    assert not (tmp_path / "source-snapshot.json").exists()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("directory,mode", [(False, 0o600), (True, 0o700)])
def test_posix_permissions_are_private_and_verified(tmp_path, monkeypatch, directory, mode) -> None:
    modes: list[int] = []
    mocked_path = SimpleNamespace(chmod=lambda value: modes.append(value),
                                  stat=lambda **kwargs: SimpleNamespace(st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | mode,
                                                                       st_dev=1, st_ino=2))
    # Keep real filesystem ownership untouched; only permission calls are mocked.
    monkeypatch.setattr(private_files, "_is_windows", lambda: False)
    monkeypatch.setattr(private_files, "_checked_path", lambda *args, **kwargs: mocked_path)
    if directory:
        # Cache keys need identity hashing, as real Path instances provide.
        class MockDirectory:
            chmod = staticmethod(mocked_path.chmod)
            stat = staticmethod(mocked_path.stat)
        mocked_path = MockDirectory()
        private_files.secure_directory(tmp_path)
    else:
        private_files.secure_file(tmp_path / "file.tmp")
    assert modes == [mode]


def test_wrong_posix_mode_verification_fails_closed(tmp_path, monkeypatch) -> None:
    mocked_path = SimpleNamespace(chmod=lambda value: None,
                                  stat=lambda **kwargs: SimpleNamespace(st_mode=stat.S_IFREG | 0o644))
    monkeypatch.setattr(private_files, "_is_windows", lambda: False)
    monkeypatch.setattr(private_files, "_checked_path", lambda *args, **kwargs: mocked_path)
    with pytest.raises(private_files.PrivateFilePermissionError, match="could not be verified"):
        private_files.secure_file(tmp_path / "file.tmp")


def test_sid_failure_does_not_use_account_name_fallback(monkeypatch) -> None:
    private_files._owner_sid.cache_clear()
    monkeypatch.setattr(private_files, "_command", lambda args: b'"fixture-user","unexpected"')
    with pytest.raises(private_files.PrivateFilePermissionError, match="SID"):
        private_files._owner_sid()
    private_files._owner_sid.cache_clear()
