#!/bin/bash
DSA_PROXY_LIB_DIR=/home/skuma24/dsa-examples

accel-config disable-device dsa0
accel-config disable-device dsa2
accel-config disable-device dsa4
accel-config disable-device dsa6

accel-config load-config -c $DSA_PROXY_LIB_DIR/memproxy-4-dsa.conf

accel-config enable-device dsa0
accel-config enable-device dsa2
accel-config enable-device dsa4
accel-config enable-device dsa6

accel-config enable-wq dsa0/wq0.0
accel-config enable-wq dsa2/wq2.0
accel-config enable-wq dsa4/wq4.0
accel-config enable-wq dsa6/wq6.0

export USESTDC_CALLS=0
export COLLECT_STATS=1
export WAIT_METHOD=yield
export DSA_MIN_BYTES=8192
#perf stat -e dsa0/event=0x1,event_category=0x0/,dsa2/event=0x1,event_category=0x0/,dsa4/event=0x1,event_category=0x0/,dsa6/event=0x1,event_category=0x0/ numactl -C 4,5 time ./dsa-memproxy-test
./dsa-memproxy-test
