# %post — runs after the package files are installed.
#
# RPM passes $1 = number of installed instances after the operation.
#   1 = first install
#   2 = upgrade (new version installed; old still present)
#
# In both cases we want to:
#   1. Create the `yggdrasil` system user/group via sysusers.d.
#   2. Create /var/lib/yggdrasil with the right ownership via tmpfiles.d.
#   3. Reload systemd so it picks up the (possibly-new) unit file.
#
# Mirrors the Debian postinst scriptlet 1:1. We deliberately do NOT
# enable or start the service — the operator needs to provision
# identity and config first.

if [ -d /run/systemd/system ]; then
    if command -v systemd-sysusers >/dev/null 2>&1; then
        systemd-sysusers /usr/lib/sysusers.d/yggdrasil.conf
    fi
    if command -v systemd-tmpfiles >/dev/null 2>&1; then
        systemd-tmpfiles --create /usr/lib/tmpfiles.d/yggdrasil.conf || :
    fi
    systemctl daemon-reload || :
fi

exit 0
