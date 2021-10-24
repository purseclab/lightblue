#!/usr/bin/env bash

APK=$1

apktool d -f ${APK} -o temp > /dev/null

if grep -qIR --include=\*.smali 'BluetoothGatt' temp; then
  echo 'Gatt'
fi

if grep -qIR --include=\*.smali 'BluetoothA2dp' temp; then
  echo 'A2dp'
fi

if grep -qIR --include=\*.smali 'BluetoothHeadset' temp; then
  echo 'Headset'
fi

if grep -qIR --include=\*.smali 'BluetoothHealth' temp; then
  echo 'HDP'
fi

if grep -qIR --include=\*.smali 'BluetoothHidDevice' temp; then
  echo 'HID'
fi

if grep -qIR --include=\*.smali 'BluetoothHidDevice' temp; then
  echo 'LE audio'
fi

rm -r temp
