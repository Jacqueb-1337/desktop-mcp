# Linux gateway packages

The Debian package is a binary-only distribution artifact. It does not contain
credentials, authorization policies, network settings, service units, or
maintainer scripts. Installing it does not start or restart a service or change
an existing deployment. The administrator must manage service configuration
independently. Existing custom gateway locations are not replaced by this package.

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
