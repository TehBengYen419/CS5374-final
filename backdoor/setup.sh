#!/usr/bin/sh

insmod backdoor.ko 2>/dev/null
major_number=$(dmesg | grep "The major number" | tail -n 1 | awk '{print $NF}')
rm /dev/backdoor 2>/dev/null
mknod /dev/backdoor c $major_number 0
