"""Binary-only gateway maintenance; never edits configuration.

The production entry point is Linux/systemd only. Transaction logic is
separate so rollback can be tested without a service or privileged access.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time

SERVICE = "desktop-mcp-gateway.service"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def regular(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f"Expected regular, non-symlink file: {path}")


def sync_dir(directory):
    if os.name == "posix":
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def staged_copy(source, destination_dir, metadata):
    fd, name = tempfile.mkstemp(prefix=".gateway-upgrade-", dir=destination_dir)
    staged = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream, source.open("rb") as original:
            shutil.copyfileobj(original, stream)
            stream.flush()
            if os.name == "posix":
                os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
            os.chmod(staged, stat.S_IMODE(metadata.st_mode))
            os.fsync(stream.fileno())
        return staged
    except BaseException:
        staged.unlink(missing_ok=True)
        raise


def upgrade(live, candidate, policy, expected, preflight, restart):
    """Replace only the binary; preserve and verify a separate rollback copy."""
    for path in (live, candidate, policy):
        regular(path)
    if live.samefile(candidate) or live.samefile(policy) or candidate.samefile(policy):
        raise ValueError("Binary, candidate and configuration must be distinct")
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or digest(candidate) != expected:
        raise ValueError("Candidate checksum mismatch")
    before = digest(live)
    policy_before = digest(policy)
    if before == expected:
        return {"changed": False, "sha256": before}
    metadata = live.stat()
    staged = staged_copy(candidate, live.parent, metadata)
    backup = None
    installed = False
    try:
        if digest(staged) != expected:
            raise ValueError("Staged checksum mismatch")
        preflight(staged, policy)
        if digest(policy) != policy_before or digest(live) != before:
            raise RuntimeError("Configuration or live binary changed during review")
        backup = staged_copy(live, live.parent, metadata)
        if digest(backup) != before:
            raise RuntimeError("Rollback backup checksum mismatch")
        os.replace(staged, live)
        installed = True
        sync_dir(live.parent)
        restart()
        if digest(live) != expected or digest(policy) != policy_before:
            raise RuntimeError("Post-upgrade integrity check failed")
        return {"changed": True, "sha256": expected, "backup": str(backup)}
    except BaseException as error:
        if installed:
            if backup is None or digest(backup) != before:
                raise RuntimeError("Rollback backup invalid; administrator recovery required") from error
            restore = staged_copy(backup, live.parent, metadata)
            os.replace(restore, live)
            sync_dir(live.parent)
            try:
                restart()
                if digest(live) != before:
                    raise RuntimeError("Restored binary checksum mismatch")
            except BaseException as rollback_error:
                raise RuntimeError(f"Rollback service check failed; backup retained at {backup}") from rollback_error
        raise
    finally:
        staged.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        parser.error("Run locally on the gateway as its administrator")
    if not Path("/run/systemd/system").is_dir():
        parser.error("systemd required")
    for path in (args.live, args.candidate, args.policy):
        if not path.is_absolute():
            parser.error("Absolute file paths required")
    # The administrator must verify the candidate's provenance independently.
    # Only the checksum-pinned candidate is invoked, and only in offline mode.
    import fcntl
    # Reject writable ancestor directories before running a staged executable
    # as root. A locally verified checksum is not sufficient in an unsafe path.
    for directory in (args.live.parent, *args.live.parent.parents):
        meta = directory.lstat()
        if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or
                meta.st_mode & 0o022):
            parser.error(f"Unsafe binary directory: {directory}")
    lock_dir = Path("/run/desktop-mcp-upgrade")
    lock_dir.mkdir(mode=0o700, exist_ok=True)
    lock_meta = lock_dir.lstat()
    if (not stat.S_ISDIR(lock_meta.st_mode) or lock_meta.st_uid != 0 or
            lock_meta.st_mode & 0o077):
        parser.error("Unsafe maintenance lock directory")
    lock_path = lock_dir / "binary.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        def preflight(binary, policy):
            result = subprocess.run([str(binary), "--review-upgrade", str(policy)],
                                    check=True, capture_output=True, text=True, timeout=15)
            report = json.loads(result.stdout)
            if (report.get("compatible") is not True or
                report.get("administrator_review_required") is not False or
                report.get("configuration_changed") is not False or
                report.get("authorization_granted") is not False):
                raise RuntimeError("Offline compatibility review did not pass")
        def restart():
            subprocess.run(["systemctl", "restart", SERVICE], check=True, timeout=30)
            time.sleep(2)
            subprocess.run(["systemctl", "is-active", "--quiet", SERVICE], check=True, timeout=10)
        print(json.dumps(upgrade(args.live, args.candidate, args.policy,
                                 args.sha256.lower(), preflight, restart)))


if __name__ == "__main__":
    main()
