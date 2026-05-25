# cmake/CPackDeb.cmake — Debian / Ubuntu package configuration.
#
# Included from the top-level CMakeLists.txt before `include(CPack)`.
# CPack's DEB generator turns this into a properly-shaped .deb whose
# layout matches what `cmake --install --prefix=/usr` produces.

# ---------------------------------------------------------- identity
set(CPACK_DEBIAN_PACKAGE_NAME    "yggdrasil")
set(CPACK_DEBIAN_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_DEBIAN_PACKAGE_RELEASE "1"
    CACHE STRING "Debian package release suffix (1, 2, ... bumped on packaging-only fixes)")

# Honour Debian's name_version-release_arch.deb convention.
set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")

# ---------------------------------------------------------- arch
#
# CPack normally calls `dpkg --print-architecture` to set the
# package's Architecture: field, falling back to `i386` when dpkg is
# absent (wrong on every modern host). When building on a non-Debian
# host (Arch in dev, Fedora / Alpine in CI) we map uname -m to the
# closest Debian-arch equivalent. Override on cross-builds via
# `-DCPACK_DEBIAN_PACKAGE_ARCHITECTURE=arm64` etc.
find_program(_DPKG_EXECUTABLE dpkg)
if(_DPKG_EXECUTABLE)
    execute_process(
        COMMAND ${_DPKG_EXECUTABLE} --print-architecture
        OUTPUT_VARIABLE _deb_arch
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
else()
    execute_process(
        COMMAND uname -m
        OUTPUT_VARIABLE _uname_m
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(_uname_m STREQUAL "x86_64")
        set(_deb_arch "amd64")
    elseif(_uname_m STREQUAL "aarch64")
        set(_deb_arch "arm64")
    elseif(_uname_m STREQUAL "armv7l")
        set(_deb_arch "armhf")
    elseif(_uname_m MATCHES "^i[3-6]86$")
        set(_deb_arch "i386")
    else()
        set(_deb_arch "${_uname_m}")
    endif()
endif()
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "${_deb_arch}"
    CACHE STRING "Debian architecture field (override for cross-builds)")
message(STATUS "CPackDeb architecture: ${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}")
unset(_dpkg_executable)
unset(_deb_arch)
unset(_uname_m)

# ---------------------------------------------------------- metadata
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE   "${PROJECT_HOMEPAGE_URL}")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "yggdrasil maintainers <${CPACK_PACKAGE_CONTACT}>")
set(CPACK_DEBIAN_PACKAGE_SECTION    "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY   "optional")
# Multi-line description. CPack injects CPACK_PACKAGE_DESCRIPTION_SUMMARY
# as the first ("synopsis") line automatically, so this value is the
# long description only. Continuation lines must start with a single
# space per Debian policy.
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION
"yggdrasil exposes TCP, UDP and HTTPS rules from a home box on a
public IP without static residential addressing. Two-mode daemon
(terminal at home, relay/gateway on a VPS); Noise_IK-authenticated
chain transport propagates rule predicates and per-flow data over
UDP without any overlay or tunnel.")

# ---------------------------------------------------------- depends
#
# libc6 / libgcc-s1 are auto-detected by dpkg-shlibdeps via
# CPACK_DEBIAN_PACKAGE_SHLIBDEPS=ON. We add `systemd` ourselves so
# the postinst can call systemd-sysusers / systemd-tmpfiles /
# systemctl daemon-reload safely. `adduser` provides deluser/delgroup
# used by the postrm `purge` path.
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_DEPENDS   "systemd, adduser")

# Recommended: install systemd-sysv when not yet present so
# `systemctl` works post-install on legacy hosts.
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "systemd-sysv")

# --------------------------------------------------------- conffiles
#
# Tell dpkg /etc/yggdrasil/config.toml.example is a conffile so
# upgrades respect operator edits (dpkg prompts on conflict).
# The example file is documentation, not active config, so users
# rarely edit it — but treating it as a conffile keeps the contract
# clean if they do.
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)

# --------------------------------------------------------- scripts
#
# postinst:  systemd-sysusers + systemd-tmpfiles + daemon-reload
# prerm:     stop the service if active (remove / upgrade)
# postrm:    daemon-reload; on purge also delete the system user
#            and /var/lib/yggdrasil
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/deb/postinst"
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/deb/prerm"
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/deb/postrm"
)
