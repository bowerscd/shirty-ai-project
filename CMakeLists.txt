# yggdrasil — CMake build / install frontend driving CPack package
# production.
#
# This file does NOT replace `cargo build` for day-to-day development.
# It's a thin wrapper that:
#
#   1. Invokes `cargo build --release --workspace --locked` out-of-tree.
#   2. Generates shell completions from the just-built binaries via
#      each binary's `completions <shell>` subcommand.
#   3. Defines install() rules placing every artefact at the layout
#      the distro packages expect (/usr/bin, /lib/systemd/system,
#      /lib/sysusers.d, /lib/tmpfiles.d, /usr/share/...).
#
# CPack generator-specific configuration lives in dedicated files
# included at the bottom (cmake/CPackDeb.cmake, cmake/CPackRpm.cmake)
# so the DEB / RPM / Arch packagers can evolve independently.
#
# Build:
#   cmake -B build
#   cmake --build build           # runs cargo build + completion gen
#   cmake --install build --prefix /usr DESTDIR=/tmp/stage   # stage
#   cpack -B build/packages -G TGZ   # produce .tar.gz of stage layout
#
# The bench-tools and cli-defs crates are deliberately NOT installed
# (bench-tools is workspace-internal tooling, cli-defs is a lib).

cmake_minimum_required(VERSION 3.20)

# ---------------------------------------------------------------- version
#
# Read [workspace.package].version from Cargo.toml. We use this as
# the package version everywhere downstream — Cargo.toml stays the
# single source of truth.

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml" _cargo_toml)
if(NOT _cargo_toml MATCHES "\\[workspace\\.package\\][^\\[]*\nversion[ \t]*=[ \t]*\"([^\"]+)\"")
    message(FATAL_ERROR
        "Could not extract version from [workspace.package] in Cargo.toml. "
        "Expected a `version = \"...\"` key under the [workspace.package] table."
    )
endif()
set(YGGDRASIL_VERSION "${CMAKE_MATCH_1}")
unset(_cargo_toml)

project(yggdrasil
    VERSION "${YGGDRASIL_VERSION}"
    DESCRIPTION "Residential reverse proxy with a chain control plane"
    HOMEPAGE_URL "https://github.com/bowerscd/yggdrasil"
    LANGUAGES NONE   # pure-Rust workspace; no C / C++ compilation
)

# ----------------------------------------------------- package version
#
# `project(VERSION ...)` must be strictly numeric (X.Y.Z), so a
# semver prerelease suffix like `-rc3` can never live in PROJECT_VERSION.
# The release workflow injects the FULL version string (e.g. 0.1.0-rc3
# for a prerelease, or 0.1.0 for a stable tag) via
# `-DYGGDRASIL_PACKAGE_VERSION=...`; it defaults to the numeric
# PROJECT_VERSION for plain local builds. Everything the packages expose
# downstream — the TGZ file name, the CPack version fields — derives from
# this, keeping Cargo.toml the single source of truth for the numeric
# base while letting the workflow stamp the rc suffix.
set(YGGDRASIL_PACKAGE_VERSION "${PROJECT_VERSION}"
    CACHE STRING "Full package version string (override for prerelease/rc builds)")

# Debian and RPM require `~` (not semver's `-`) as the prerelease
# separator so that 0.1.0~rc3 sorts BEFORE the final 0.1.0 in
# `dpkg --compare-versions` / `rpmdev-vercmp`. semver uses `-`. Translate
# for the native-package version fields; a stable version with no suffix
# is unaffected (the REPLACE is a no-op).
string(REPLACE "-" "~"
    YGGDRASIL_NATIVE_PACKAGE_VERSION "${YGGDRASIL_PACKAGE_VERSION}")
message(STATUS "Package version: ${YGGDRASIL_PACKAGE_VERSION} "
               "(native: ${YGGDRASIL_NATIVE_PACKAGE_VERSION})")
# GNUInstallDirs normally special-cases CMAKE_INSTALL_PREFIX=/usr to
# put SYSCONFDIR at /etc and LOCALSTATEDIR at /var (the Linux distro
# convention — distro packages install binaries under /usr but config
# under /etc). That special-case is gated on CMAKE_SYSTEM_NAME, which
# our `LANGUAGES NONE` project() does NOT set, so we apply the
# convention ourselves before including GNUInstallDirs.
if(CMAKE_INSTALL_PREFIX STREQUAL "/usr")
    set(CMAKE_INSTALL_SYSCONFDIR    "/etc" CACHE PATH "C-style system config dir")
    set(CMAKE_INSTALL_LOCALSTATEDIR "/var" CACHE PATH "C-style local state dir")
    set(CMAKE_INSTALL_RUNSTATEDIR   "/run" CACHE PATH "C-style run state dir")
endif()

include(GNUInstallDirs)

# ---------------------------------------------------------------- cargo
#
# We require cargo at build time; the rust-toolchain.toml in-tree
# pins the actual rustc version cargo will resolve. Don't try to
# enforce a minimum rustc here — let cargo do it via the toolchain
# file, so the error message points the user at the right knob.

find_program(CARGO_EXECUTABLE cargo REQUIRED)
message(STATUS "Using cargo: ${CARGO_EXECUTABLE}")

set(CARGO_TARGET_DIR "${CMAKE_BINARY_DIR}/cargo"
    CACHE PATH "Cargo target directory (out-of-tree)")
set(CARGO_PROFILE "release"
    CACHE STRING "Cargo build profile (release or dev)")
option(CARGO_LOCKED
    "Pass --locked to cargo (CI / release builds: ON; dev: OFF)" ON)

set(_cargo_args build --workspace
                      --bin yggdrasil
                      --bin yggdrasilctl)
if(CARGO_PROFILE STREQUAL "release")
    list(APPEND _cargo_args --release)
endif()
if(CARGO_LOCKED)
    list(APPEND _cargo_args --locked)
endif()

set(YGGDRASIL_BIN    "${CARGO_TARGET_DIR}/${CARGO_PROFILE}/yggdrasil")
set(YGGDRASILCTL_BIN "${CARGO_TARGET_DIR}/${CARGO_PROFILE}/yggdrasilctl")

# Track Rust sources so re-running `cmake --build` only re-invokes
# cargo when something actually changed. CONFIGURE_DEPENDS reruns
# the glob at build time (CMake 3.12+).
file(GLOB_RECURSE _rust_sources CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/crates/*.rs"
    "${CMAKE_CURRENT_SOURCE_DIR}/crates/*.toml"
)
list(APPEND _rust_sources
    "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml"
    "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.lock"
    "${CMAKE_CURRENT_SOURCE_DIR}/rust-toolchain.toml"
)

add_custom_command(
    OUTPUT "${YGGDRASIL_BIN}" "${YGGDRASILCTL_BIN}"
    COMMAND "${CMAKE_COMMAND}" -E env
            "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"
            "${CARGO_EXECUTABLE}" ${_cargo_args}
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    DEPENDS ${_rust_sources}
    COMMENT "cargo ${_cargo_args}"
    VERBATIM
)

add_custom_target(cargo_binaries ALL
    DEPENDS "${YGGDRASIL_BIN}" "${YGGDRASILCTL_BIN}"
)

# --------------------------------------------------------- completions
#
# Each `yggdrasil completions <shell>` and `yggdrasilctl completions
# <shell>` writes a completion script to stdout. We run the
# just-built binary at build time and capture the output to a file
# per (binary × shell). Bash drops the extension on install (matches
# bash-completion(7) convention); zsh uses the `_NAME` autoload
# format; fish keeps the `.fish` extension.

set(_completions_dir "${CMAKE_BINARY_DIR}/completions")
file(MAKE_DIRECTORY "${_completions_dir}")

set(_completion_outputs)
foreach(_binary IN ITEMS yggdrasil yggdrasilctl)
    if(_binary STREQUAL "yggdrasil")
        set(_binary_path "${YGGDRASIL_BIN}")
    else()
        set(_binary_path "${YGGDRASILCTL_BIN}")
    endif()
    foreach(_shell IN ITEMS bash zsh fish)
        if(_shell STREQUAL "bash")
            set(_outfile "${_completions_dir}/${_binary}.bash")
        elseif(_shell STREQUAL "zsh")
            set(_outfile "${_completions_dir}/_${_binary}")
        else()
            set(_outfile "${_completions_dir}/${_binary}.fish")
        endif()
        add_custom_command(
            OUTPUT "${_outfile}"
            COMMAND "${_binary_path}" completions ${_shell} > "${_outfile}"
            DEPENDS "${_binary_path}"
            COMMENT "Generating ${_shell} completions for ${_binary}"
            VERBATIM
        )
        list(APPEND _completion_outputs "${_outfile}")
    endforeach()
endforeach()

add_custom_target(completions ALL DEPENDS ${_completion_outputs})

# ---------------------------------------------------------------- install
#
# The canonical layout — every distro package format installs to
# exactly these paths. systemd unit, sysusers, tmpfiles all go under
# /lib/... (not under CMAKE_INSTALL_LIBDIR which on Debian-multiarch
# would be /lib/x86_64-linux-gnu — wrong for systemd files).

# Binaries → /usr/bin
install(PROGRAMS "${YGGDRASIL_BIN}" "${YGGDRASILCTL_BIN}"
        DESTINATION "${CMAKE_INSTALL_BINDIR}")

# systemd unit → /lib/systemd/system (NOT under prefix on most distros)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/contrib/systemd/yggdrasil.service"
        DESTINATION "lib/systemd/system")

# sysusers.d → /lib/sysusers.d
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/contrib/sysusers.d/yggdrasil.conf"
        DESTINATION "lib/sysusers.d")

# tmpfiles.d → /lib/tmpfiles.d
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/contrib/tmpfiles.d/yggdrasil.conf"
        DESTINATION "lib/tmpfiles.d")

# Example config → /etc/yggdrasil/config.toml.example
# The package deliberately does NOT install config.toml itself; the
# operator copies the .example and edits it (or runs the request /
# grant ceremony described in docs/quickstart.md).
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/contrib/config/config.toml.example"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/yggdrasil")

# Completions — bash / zsh / fish.
install(FILES "${_completions_dir}/yggdrasil.bash"
        DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/bash-completion/completions"
        RENAME "yggdrasil")
install(FILES "${_completions_dir}/yggdrasilctl.bash"
        DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/bash-completion/completions"
        RENAME "yggdrasilctl")
install(FILES "${_completions_dir}/_yggdrasil" "${_completions_dir}/_yggdrasilctl"
        DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/zsh/site-functions")
install(FILES "${_completions_dir}/yggdrasil.fish"
              "${_completions_dir}/yggdrasilctl.fish"
        DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/fish/vendor_completions.d")

# Docs → /usr/share/doc/yggdrasil
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/README.md"
        DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/docs/"
        DESTINATION "${CMAKE_INSTALL_DOCDIR}"
        FILES_MATCHING PATTERN "*.md")

# License file — conditional install. Cargo.toml declares
# `license = "MIT"`. The LICENSE file at the repo root ships under
# /usr/share/doc/yggdrasil/ alongside README and docs/.
set(_license_path "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
if(EXISTS "${_license_path}")
    install(FILES "${_license_path}"
            DESTINATION "${CMAKE_INSTALL_DOCDIR}")
else()
    message(WARNING
        "LICENSE file is referenced by Cargo.toml's `license = \"MIT\"` "
        "but does not exist in the repository root. Packages built from this tree will ship "
        "without the license text — fix before publishing."
    )
endif()

# ---------------------------------------------------------------- cpack
#
# Generator-agnostic CPack defaults. Per-generator configuration
# (DEB control fields, RPM scriptlets, etc.) lives in dedicated
# include files added in the cpack-deb / cpack-rpm steps. Until
# those land, `cpack -G TGZ` produces a tarball of the install
# layout, which the PR-gate CI uses as a packaging smoke check.

set(CPACK_PACKAGE_NAME "yggdrasil")
set(CPACK_PACKAGE_VERSION "${YGGDRASIL_PACKAGE_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_HOMEPAGE_URL "${PROJECT_HOMEPAGE_URL}")
set(CPACK_PACKAGE_VENDOR "yggdrasil maintainers")
set(CPACK_PACKAGE_CONTACT "https://github.com/bowerscd/yggdrasil/issues")
set(CPACK_PACKAGE_FILE_NAME
    "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")

# Default to TGZ; DEB / RPM / Arch generators are opted in via the
# per-generator configuration files below. CPack reads each file's
# variables before `include(CPack)` resolves the active generator
# set, so the order is "set defaults → include per-generator → include
# CPack".
set(CPACK_GENERATOR "TGZ")
set(CPACK_SOURCE_GENERATOR "")   # source packaging unused — we ship binaries

# Stage absolute install destinations (notably /etc/yggdrasil) under
# CPack's DESTDIR rather than literally writing to the host. Without
# this, `cpack -G TGZ` would try to mkdir /etc/yggdrasil on the host
# and fail without root.
set(CPACK_SET_DESTDIR ON)
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")

# Per-generator configuration. Each file is silently included if it
# exists; the corresponding generator is appended to CPACK_GENERATOR.
# This lets the workflow build a subset (e.g. DEB-only on a Debian
# runner) by overriding CPACK_GENERATOR on the cpack command line.
foreach(_gen_file_pair
        "CPackDeb.cmake;DEB"
        "CPackRpm.cmake;RPM")
    list(GET _gen_file_pair 0 _gen_file)
    list(GET _gen_file_pair 1 _gen_name)
    set(_gen_path "${CMAKE_CURRENT_SOURCE_DIR}/cmake/${_gen_file}")
    if(EXISTS "${_gen_path}")
        include("${_gen_path}")
        list(APPEND CPACK_GENERATOR "${_gen_name}")
    endif()
endforeach()
list(REMOVE_DUPLICATES CPACK_GENERATOR)
message(STATUS "CPack generators: ${CPACK_GENERATOR}")

include(CPack)
