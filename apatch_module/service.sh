#!/system/bin/sh
#
# ptehook APatch module boot script.
# Loads KPM and starts the ptehookd daemon on device boot.
#
MODDIR=${0%/*}
DATADIR=/data/adb/ptehook
LOGFILE=$DATADIR/ptehookd.log

# Wait for boot to complete
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 1
done
sleep 5

# Ensure data directory exists
mkdir -p $DATADIR/profiles

# Deploy binaries from module to data partition
for bin in ptehookd ptehook_ctl pte_scan; do
    if [ -f "$MODDIR/data/$bin" ]; then
        cp -f "$MODDIR/data/$bin" "$DATADIR/$bin"
        chmod 755 "$DATADIR/$bin"
        chown root:root "$DATADIR/$bin"
    fi
done

# Deploy KPM
if [ -f "$MODDIR/data/ptehook_planc_v2.kpm" ]; then
    cp -f "$MODDIR/data/ptehook_planc_v2.kpm" "$DATADIR/ptehook_planc_v2.kpm"
fi

# Read superkey
SK=$(cat "$DATADIR/superkey" 2>/dev/null)
if [ -z "$SK" ]; then
    echo "$(date): ERROR: no superkey at $DATADIR/superkey" >> $LOGFILE
    exit 1
fi

# Load KPM if not already loaded
KPM_LIST=$(/data/adb/kpatch "$SK" kpm list 2>&1)
if echo "$KPM_LIST" | grep -q "ptehook-planc-v2"; then
    echo "$(date): KPM already loaded" >> $LOGFILE
else
    /data/adb/kpatch "$SK" kpm load "$DATADIR/ptehook_planc_v2.kpm" >> $LOGFILE 2>&1
    echo "$(date): KPM loaded" >> $LOGFILE
fi

# Kill any stale daemon
killall ptehookd 2>/dev/null
sleep 1

# Start daemon
nohup "$DATADIR/ptehookd" \
    --superkey-file="$DATADIR/superkey" \
    --profiles-dir="$DATADIR/profiles" \
    --bin-dir="$DATADIR" \
    --log="$LOGFILE" \
    >> $LOGFILE 2>&1 &

echo "$(date): ptehookd started, pid=$!" >> $LOGFILE
