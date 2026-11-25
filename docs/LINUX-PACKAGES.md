# Linux gateway packages

The Debian package contains the static gateway binary, enrollment helper,
systemd socket/template units and conditional package hooks. It contains no
credentials, authorization policies or network settings. It does not restart
the gateway or replace custom gateway locations or local unit overrides.

Enrollment activation requires an already configured gateway. If prerequisites
are missing, the installer reports why activation was skipped. An administrator
can retry after completing gateway setup using the packaged enable-enrollment
utility at `/usr/lib/desktop-mcp/enable-enrollment`. Package installation does not enroll
individual peers or grant remote permissions.

## Build environment

Use a Linux build host with the Rust version pinned in gateway/Cargo.toml,
musl-tools, a C toolchain, binutils and dpkg-dev. For x86_64 Linux, build the
gateway for x86_64-unknown-linux-musl with Cargo's locked dependencies. Run
the gateway tests on the build host before packaging. The resulting binary
must be a static ELF; the packaging script rejects architecture mismatches and
dynamic dependencies. The package contains no host-specific files.

## Package

    bash docs/build-gateway-deb.sh <static-gateway-binary> <version> amd64 <output-directory>

The script supports amd64 and arm64, subject to the matching static binary
being built and tested independently. It emits a versioned .deb and a SHA-256
checksum. Debian/Ubuntu-family systems can manage this binary with dpkg.
The packaged executable resides in /usr/lib/desktop-mcp/desktop-mcp-gateway.
This is not a complete gateway provisioning or migration installer.

## Verification

Use dpkg-deb --info and --contents to inspect the metadata and payload. Extract
into a disposable directory, compare the packaged executable to the build
artifact, verify the checksum and run the extracted executable's version and
offline validation commands. Test service integration separately in a
disposable environment before deploying a production update.

## Isolated package lifecycle regression

The fixture-only lifecycle test uses a temporary root and its own dpkg database.
It installs two harmless static executables in succession, checks same-version
reinstall and downgrade, and removes and purges the package. It verifies file
contents, ownership and mode of dummy external settings, pairings, certificate,
legacy executable and service unit at every step. No service is started or
changed. This tests the package-managed binary lifecycle, not legacy service
migration, automatic rollback on service failure, or live connectivity.

Run only in a disposable Linux test environment with dpkg and a static C toolchain:

    sudo bash docs/test-gateway-package-lifecycle.sh

## Release automation

The Linux gateway release packages workflow builds and tests native amd64 and arm64 static binaries on GitHub-hosted Linux runners. A manual workflow run produces downloadable CI artifacts without publishing. For packaging-only fixes, set the optional `debian_revision` input to a positive integer (for example `1` produces `0.3.6-1` packages from the v0.3.6 gateway binary). This lets dpkg distinguish packaging updates without changing the executable's version. A version-tag run verifies both architectures and attaches their versioned Debian packages and individual SHA-256 files to the existing GitHub release. Create the release as a draft before pushing the matching version tag, or manually attach the verified workflow artifacts before publishing. The workflow does not install or restart the NAS gateway. Windows installer/tray assets remain a separate build step; keep both platforms on the same source revision and version.
