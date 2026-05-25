# cmake/CPackRpm.cmake — RPM (Fedora / RHEL / openSUSE) package config.
#
# Included from the top-level CMakeLists.txt before `include(CPack)`.
# CPack's RPM generator builds a fully-shaped .rpm whose layout
# matches what `cmake --install --prefix=/usr` produces.

# ---------------------------------------------------------- identity
set(CPACK_RPM_PACKAGE_NAME    "yggdrasil")
set(CPACK_RPM_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_RPM_PACKAGE_RELEASE "1"
    CACHE STRING "RPM Release: tag (1, 2, ... bumped on packaging-only fixes)")

# name-version-release.arch.rpm — RPM standard naming.
set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")

# ---------------------------------------------------------- arch
#
# CPack normally calls `rpmbuild --eval %{_arch}` to derive the
# package architecture. When `rpmbuild` is missing (we're building on
# Arch / Debian / Alpine), fall back to a uname -m → RPM-arch mapping.
find_program(_RPMBUILD_EXECUTABLE rpmbuild)
if(NOT _RPMBUILD_EXECUTABLE)
    execute_process(
        COMMAND uname -m
        OUTPUT_VARIABLE _uname_m
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(CPACK_RPM_PACKAGE_ARCHITECTURE "${_uname_m}"
        CACHE STRING "RPM architecture (override for cross-builds)")
    message(STATUS "CPackRpm architecture: ${CPACK_RPM_PACKAGE_ARCHITECTURE} (rpmbuild not found, derived from uname -m)")
    unset(_uname_m)
else()
    message(STATUS "CPackRpm: rpmbuild found at ${_RPMBUILD_EXECUTABLE}; arch derived automatically")
endif()

# ---------------------------------------------------------- metadata
set(CPACK_RPM_PACKAGE_LICENSE     "MIT")
set(CPACK_RPM_PACKAGE_GROUP       "Applications/Internet")
set(CPACK_RPM_PACKAGE_URL         "${PROJECT_HOMEPAGE_URL}")
set(CPACK_RPM_PACKAGE_VENDOR      "${CPACK_PACKAGE_VENDOR}")
set(CPACK_RPM_PACKAGE_SUMMARY     "${PROJECT_DESCRIPTION}")
set(CPACK_RPM_PACKAGE_DESCRIPTION
"yggdrasil exposes TCP, UDP and HTTPS rules from a home box on a
public IP without static residential addressing. Two-mode daemon
(terminal at home, relay/gateway on a VPS); Noise_IK-authenticated
chain transport propagates rule predicates and per-flow data over
UDP without any overlay or tunnel.")

# ---------------------------------------------------------- depends
#
# RPM auto-generates ELF library dependencies via rpmbuild's
# find-requires script, similar to dpkg-shlibdeps. We add the
# scriptlet helpers explicitly.
#
# `systemd` provides systemctl, systemd-sysusers, systemd-tmpfiles.
# `shadow-utils` provides useradd/userdel/groupadd/groupdel (the RPM
# equivalent of Debian's adduser package).
# `glibc` is auto-detected from the binary's NEEDED libc.so.6.
set(CPACK_RPM_PACKAGE_REQUIRES "systemd, shadow-utils")

# Don't let rpmbuild auto-generate Provides for the binaries (they're
# not libraries; nothing in another package depends on them).
set(CPACK_RPM_PACKAGE_AUTOREQ ON)
set(CPACK_RPM_PACKAGE_AUTOPROV OFF)

# --------------------------------------------------------- conffiles
#
# Mark the example config + every shipped systemd asset as %config so
# operator edits survive upgrades (rpm renames in-place if user
# modified, with a `.rpmnew` suffix for the package's version).
set(CPACK_RPM_PACKAGE_CONFIG_FILE_LIST
    "/etc/yggdrasil/config.toml.example"
    "/usr/lib/systemd/system/yggdrasil.service"
    "/usr/lib/sysusers.d/yggdrasil.conf"
    "/usr/lib/tmpfiles.d/yggdrasil.conf"
)

# ----------------------------------------------------- system dirs
#
# Tell RPM that these directories already exist on every system; we
# don't own them. Without this, rpmbuild's auto-find-provides claims
# we own /usr/bin, /etc, etc., and dnf refuses the install with a
# file conflict against filesystem.rpm.
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
    "/etc"
    "/usr"
    "/usr/bin"
    "/usr/lib"
    "/usr/lib/systemd"
    "/usr/lib/systemd/system"
    "/usr/lib/sysusers.d"
    "/usr/lib/tmpfiles.d"
    "/usr/share"
    "/usr/share/doc"
    "/usr/share/bash-completion"
    "/usr/share/bash-completion/completions"
    "/usr/share/zsh"
    "/usr/share/zsh/site-functions"
    "/usr/share/fish"
    "/usr/share/fish/vendor_completions.d"
)

# --------------------------------------------------------- scripts
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/rpm/post.sh")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/rpm/preun.sh")
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/rpm/postun.sh")
