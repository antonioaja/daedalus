#!/bin/sh
# Script to compile for all platforms
# cross-rs must be installed

cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin
cross build --release --target x86_64-unknown-linux-gnu
cross build --release --target aarch64-unknown-linux-gnu
cargo build --release --target x86_64-pc-windows-gnu
# cross build --release --target aarch64-pc-windows-msvc