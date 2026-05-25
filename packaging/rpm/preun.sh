# %preun — runs BEFORE the package files are removed.
#
# RPM passes $1 = number of installed instances *after* the operation.
#   0 = final uninstall (this is the last copy)
#   1 = upgrade preun (about to remove the OLD copy; new is installed)
#
# We only want to stop the service on a real uninstall — on upgrade,
# the old daemon stays running until %post of the new package runs.

if [ "$1" = "0" ]; then
    if [ -d /run/systemd/system ]; then
        systemctl stop yggdrasil.service >/dev/null 2>&1 || :
        systemctl disable yggdrasil.service >/dev/null 2>&1 || :
    fi
fi

exit 0
