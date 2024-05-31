#!/bin/sh

insmod ../mod/ekcfi.ko
../ebpf/policy
../ebpf/policy_ret
../ekcfi_test/target/release/ekcfi_test -mtrace 2 vmlinux
