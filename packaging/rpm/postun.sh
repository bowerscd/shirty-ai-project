# %postun — runs AFTER the package files are removed.
#
# RPM passes $1 = number of installed instances *after* the operation.
#   0 = final uninstall (no copies left)
#   1 = upgrade postun (old version cleaned up; new still installed)
#
# On upgrade we let the new package's %post handle daemon-reload.
# On final uninstall we also remove the system user and per-host state
# under /var/lib/yggdrasil. /etc/yggdrasil is left intact so the
# operator can preserve identity / enrollment for a future reinstall.

if [ "$1" = "0" ]; then
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || :
    fi
    rm -rf /var/lib/yggdrasil
    if getent passwd yggdrasil >/dev/null; then
        userdel yggdrasil >/dev/null 2>&1 || :
    fi
    if getent group yggdrasil >/dev/null; then
        groupdel yggdrasil >/dev/null 2>&1 || :
    fi
fi

exit 0
