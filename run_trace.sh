#!/bin/sh

insmod ../mod/ekcfi.ko
../ebpf/trace $1
../ekcfi_test/target/release/ekcfi_test -mtrace $1 vmlinux
