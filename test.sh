#!/bin/bash
DSA_PERF_MICROS_DIR=/home/reddy/gitrepos/dsa-perf-micros
DSA_WQTYPE="s"
WQ_NAME=wq0.0

if [[ "$1" == "d" ]]; then
	echo "************ Running Dedicated WQ Testing using $WQ_NAME  ***********"
	DSA_WQTYPE="d"
	export WQ_DEDICATED=1
else
	echo "************ Running Shared WQ Testing using $WQ_NAME  ***********"
	DSA_WQTYPE="s"
	export WQ_DEDICATED=0
fi

$DSA_PERF_MICROS_DIR/scripts/setup_dsa.sh -d dsa0
$DSA_PERF_MICROS_DIR/scripts/setup_dsa.sh -d dsa0 -w 1 -m $DSA_WQTYPE  -e 1
export LD_PRELOAD=./dsa-memproxy.so
export WQ_PATH="/dev/dsa/${WQ_NAME}"
export USESTDC_CALLS=0
export COLLECT_STATS=1
dsa-memproxy-test
