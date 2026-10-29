#!/bin/sh
ip link show dummy0 >/dev/null 2>&1 || ip link add dummy0 type dummy
ip link set dummy0 up
