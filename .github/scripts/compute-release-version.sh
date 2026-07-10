#!/usr/bin/env bash
#
# compute-release-version.sh — derive the release version + prerelease
# flag for the Release workflow, and emit them as `key=value` lines
# suitable for appending to $GITHUB_OUTPUT.
#
# Inputs (from the environment / working tree):
#   GITHUB_REF   refs/heads/master           → rolling release candidate
#                refs/tags/X.Y.Z             → stable release
#   Cargo.toml   [workspace.package].version → numeric base X.Y.Z
#                                              (the single source of truth
#                                              CMake also reads)
#   git tags     existing X.Y.Z (stable) and X.Y.Z-rcN (prereleases)
#
# Output (stdout, one `key=value` per line):
#   version=X.Y.Z            (stable)  |  X.Y.Z-rcN  (prerelease)
#   prerelease=false|true
#
# Semantics:
#   * A stable tag push publishes exactly that version. The tag MUST
#     equal the Cargo.toml version so the packages CMake stamps (which
#     read Cargo.toml) match the release tag.
#   * A master push publishes a release candidate for the *next*
#     version. An rc is a preview of what comes AFTER the last stable
#     release, so its base X.Y.Z MUST be strictly greater than the last
#     stable tag — `0.1.0-rc1` sorts BELOW `0.1.0`, so it is only a valid
#     preview while `0.1.0` has not yet been tagged. Once `0.1.0` ships,
#     bump Cargo.toml (e.g. to `0.1.1`) and rc builds resume as
#     `0.1.1-rcN`. If Cargo.toml is not ahead of the last stable tag the
#     job fails, forcing the bump rather than publishing a downgrade.
#   * The rc counter is monotonic *per base version*: the next rc for a
#     given X.Y.Z is (highest existing X.Y.Z-rcN) + 1. So 0.1.0-rc1,
#     0.1.0-rc2, … and, independently, 0.2.0-rc1, 0.2.0-rc2, …
#
set -euo pipefail

die() { echo "::error::$*" >&2; exit 1; }

ref="${GITHUB_REF:-}"
[[ -n "$ref" ]] || die "GITHUB_REF is not set"

# --- numeric base version from Cargo.toml [workspace.package] ----------
cargo_version="$(
    awk '
        /^\[workspace\.package\]/ { in_sec = 1; next }
        /^\[/                     { in_sec = 0 }
        in_sec && /^[ \t]*version[ \t]*=/ {
            gsub(/.*=[ \t]*"|".*/, "")
            print
            exit
        }
    ' Cargo.toml
)"
[[ "$cargo_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || die "Cargo.toml [workspace.package].version '$cargo_version' is not a bare X.Y.Z"

# semver_gt A B → success iff A > B under version sort.
semver_gt() {
    [[ "$1" != "$2" ]] \
        && [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" == "$1" ]]
}

last_stable="$(git tag -l | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n1 || true)"

# --- stable release: tag push ------------------------------------------
if [[ "$ref" == refs/tags/* ]]; then
    tag="${ref#refs/tags/}"
    [[ "$tag" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || die "tag '$tag' is not a bare stable X.Y.Z tag"
    [[ "$tag" == "$cargo_version" ]] \
        || die "stable tag '$tag' does not match Cargo.toml version '$cargo_version' — bump Cargo.toml or retag"
    echo "version=$tag"
    echo "prerelease=false"
    exit 0
fi

# --- rolling release candidate: master push ----------------------------
base="$cargo_version"
if [[ -n "$last_stable" ]]; then
    semver_gt "$base" "$last_stable" \
        || die "Cargo.toml version '$base' is not greater than the last stable tag '$last_stable'; an rc must preview the NEXT release — bump [workspace.package].version"
fi

# Per-base monotonic rc counter: highest existing <base>-rcN, plus one.
last_n="$(
    git tag -l "${base}-rc*" \
        | sed -n "s/^${base}-rc\([0-9]\{1,\}\)$/\1/p" \
        | sort -n | tail -n1 || true
)"
n=$(( ${last_n:-0} + 1 ))
echo "version=${base}-rc${n}"
echo "prerelease=true"
