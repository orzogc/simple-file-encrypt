#!/bin/sh
# musl C toolchain shim: lets cargo and the cc crate use zig as the
# compiler and linker for aarch64-unknown-linux-musl. Plain `zig cc` is
# not enough — the cc crate misparses multi-word CC, and linking needs
# cargo-zigbuild's crt de-duplication.
exec cargo-zigbuild zig cc -- -target aarch64-linux-musl "$@"
