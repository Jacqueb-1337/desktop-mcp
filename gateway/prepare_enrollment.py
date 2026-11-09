#!/usr/bin/env python3
"""Prepare a reviewed second-PC enrollment without changing the live gateway."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def read_json(path):
    with path.open(encoding="utf-8-sig") as source:
        return json.load(source)


def validate_identity(identity):
    if not isinstance(identity, dict) or set(identity) != {"host_id", "public_key"}:
        raise ValueError("Expected only host_id and public_key in the device record.")
    host, key = identity["host_id"], identity["public_key"]
    if not isinstance(key, str) or not re.fullmatch("[a-f0-9]{64}", key):
        raise ValueError("Expected a lowercase Ed25519 public key in hex.")
    if host != hashlib.sha256(bytes.fromhex(key)).hexdigest()[:32]:
        raise ValueError("Host ID does not match its public key.")
    return host


def host_records(config, limit):
    if (
        not isinstance(config, dict)
        or set(config) != {"version", "hosts"}
        or type(config["version"]) is not int
        or config["version"] != 1
        or not isinstance(config["hosts"], list)
        or len(config["hosts"]) >= limit
    ):
        raise ValueError("Invalid config version, format, or host capacity.")
    return config["hosts"]


def read_setup_code():
    code = input("Paste the PC's Desktop MCP setup code: ").strip()
    if not re.fullmatch("DM1-[a-f0-9]{64}", code):
        raise ValueError("Expected the full setup code starting with DM1-.")
    key = code.removeprefix("DM1-")
    return {"host_id": hashlib.sha256(bytes.fromhex(key)).hexdigest()[:32], "public_key": key}


def prepare(args):
    device = read_setup_code() if args.device_code else read_json(args.device)
    host = validate_identity(device)
    allowlist, policy = read_json(args.allowlist), read_json(args.policy)
    allowed_hosts = host_records(allowlist, 64)
    scopes = host_records(policy, 64)

    known_hosts = set()
    for identity in allowed_hosts:
        existing = validate_identity(identity)
        if existing in known_hosts:
            raise ValueError("Duplicate identity in the current allowlist.")
        known_hosts.add(existing)

    scoped_hosts = set()
    for scope in scopes:
        if (
            not isinstance(scope, dict)
            or set(scope) != {"host_id", "workspace_id", "tools"}
            or not isinstance(scope["host_id"], str)
            or scope["host_id"] not in known_hosts
            or scope["host_id"] in scoped_hosts
            or scope["workspace_id"] != "default"
            or not isinstance(scope["tools"], list)
            or any(tool not in ("git_status", "fs_read", "request_permission", "system_volume_status", "admin_command") for tool in scope["tools"])
            or len(set(scope["tools"])) != len(scope["tools"])
        ):
            raise ValueError("Invalid, duplicate, or unrecognized scope in the current policy.")
        scoped_hosts.add(scope["host_id"])

    if host in known_hosts:
        raise ValueError("This device is already registered.")

    tools = ["request_permission", "git_status"]
    if args.allow_file_read:
        tools.append("fs_read")
    if args.allow_system_volume_status:
        tools.append("system_volume_status")
    if args.allow_admin_commands:
        tools.append("admin_command")
    allowed_hosts.append(device)
    scopes.append({"host_id": host, "workspace_id": "default", "tools": tools})

    # mkdir without exist_ok ensures we never overwrite a live or staged config.
    args.output.mkdir(mode=0o700)
    for name, config in (("allowlist.json", allowlist), ("policy.json", policy)):
        with (args.output / name).open("x", encoding="utf-8") as output:
            json.dump(config, output, indent=2)
            output.write("\n")

    print(f"Prepared {host} / default with {', '.join(tools)}.")
    print(f"Review both files under {args.output}. The running gateway was not changed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    identity = parser.add_mutually_exclusive_group(required=True)
    identity.add_argument("--device", type=Path, help="Public identity JSON file")
    identity.add_argument("--device-code", action="store_true", help="Prompt for the PC's setup code")
    for name in ("allowlist", "policy", "output"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--allow-file-read", action="store_true")
    parser.add_argument("--allow-system-volume-status", action="store_true")
    parser.add_argument("--allow-admin-commands", action="store_true")
    try:
        prepare(parser.parse_args())
    except (EOFError, OSError, ValueError) as error:
        parser.exit(1, f"Enrollment preparation failed: {error}\n")


if __name__ == "__main__":
    main()
