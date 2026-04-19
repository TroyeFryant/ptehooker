#!/system/bin/sh
#
# ptehook APatch module install script.
#
SKIPUNZIP=1

ui_print "- ptehook: installing on-device auto-hook framework"

# Extract module files
unzip -o "$ZIPFILE" -d "$MODPATH" >&2

# Set permissions
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/data/ptehookd" 0 0 0755
set_perm "$MODPATH/data/ptehook_ctl" 0 0 0755
set_perm "$MODPATH/data/pte_scan" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755

# Ensure data directories exist
mkdir -p /data/adb/ptehook/profiles

ui_print "- Binaries installed to module directory"
ui_print "- Ensure /data/adb/ptehook/superkey is configured"
ui_print "- Place hook profiles in /data/adb/ptehook/profiles/"
ui_print "- Reboot to activate"
