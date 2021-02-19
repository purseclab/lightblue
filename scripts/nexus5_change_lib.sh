set -x
adb push $1 /sdcard/
adb shell "su -c 'mount -o remount,rw /system'"
adb shell "su -c 'chmod 644 /sdcard/$1'"
adb shell "su -c 'cp /sdcard/$1 /system/lib/hw/bluetooth.default.so'"
adb reboot
