#!/usr/bin/env bash

set -eu

# Linking the script as the pre-commit hook
SCRIPT_PATH=$(realpath "$0")
HOOK_PATH=$(git rev-parse --git-dir)/hooks/pre-commit
if [ "$(realpath "$HOOK_PATH")" != "$SCRIPT_PATH" ]; then
    read -p "Link this script as the git pre-commit hook to avoid further manual running? (y/N): " answer
    if [[ $answer =~ ^[Yy]$ ]]; then
        ln -sf "$SCRIPT_PATH" "$HOOK_PATH"
    fi
fi

set -x

# Install tools
cargo clippy --version &>/dev/null || rustup component add clippy
cargo machete --version &>/dev/null || cargo install --locked cargo-machete
cargo sort --version &>/dev/null || cargo install --locked cargo-sort
typos --version &>/dev/null || cargo install --locked typos-cli

rustup toolchain list | grep -q 'nightly' || rustup toolchain install nightly
cargo +nightly fmt --version &>/dev/null || rustup component add rustfmt --toolchain nightly

# Checks
typos .
cargo machete
cargo +nightly fmt -- --check
cargo sort -c
cargo clippy --all-targets --all-features -- -D warnings
cargo rustdoc --all-features -- -D warnings

cargo test --doc
cargo test --all-targets
cargo test --all-targets --features forwarded-header
