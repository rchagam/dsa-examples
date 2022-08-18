# dsa-examples
DSA sample code for memory proxy testing. Code includes memory fill, move, copy and compare DSA operations.
This is sample code which reuses dsa-perf-micros source code snippets to show how DSA offload capability 
can be tested without changing application code by using LD_PRELOAD option.

```bash
dsa-memproxy.c: DSA memory operations proxy shared library
dsa-memproxy-test.c: Sample multi-threaded test sample
test.sh: Sample test script to test shared and dedicated WQ configs

Following environment variables control the behavior of DSA proxy operations:
	WQ_DEDICATED=1 (for dedicated queue), 0 (for shared queue)
	WQ_PATH=/dev/dsa/<wq> for WQ name
	USESTDC_CALLS=0 (uses std c memory functions only), 1 (uses DSA calls, in case of failures - reverts to std c lib call)
	COLLECT_STATS=1 (enables stats collection - #of operations, avg latency for each function>, 0 (disables stats collection)
	DSA_MIN_BYTES=xxxx (specifies minimum size needed for DSA operation execution, default is 4096 bytes)
```

## Build

```bash
make
```

## Test
```bash
	1. Make changes to test.sh to point to dsa-perf-micros script directory
	2. <Shared WQ>: test.sh 
	3. <Dedicated WQ>: test.sh d
	4. <Testing with real binary - e.g. CacheBench>
		4a. export all environment variables including LD_PRELOAD
		4b. run cachebench 
		export LD_PRELOAD=<dir>/dsa-memproxy.so
		export WQ_PATH="/dev/dsa/wq0.0"
		export WQ_DEDICATED=0
		export USESTDC_CALLS=0
		export COLLECT_STATS=1

		<CBENCH_DIR>/cachebench -json_test_config <json file> --progress_stats_file=dsaproxy.log --report_api_latency
		******** Number of Memory Operations ********
							 <***** stdc calls    *****> <***** dsa (success) *****> <***** dsa (failed)  *****>
		Byte Range        -- set    cpy    mov    cmp    set    cpy    mov    cmp    set    cpy    mov    cmp
			   0-4095     -- 2218   106326 131691 5668   0      0      0      0      0      0      0      0
			4096-8191     -- 0      0      0      0      2      6      34     0      0      0      0      0
			8192-12287    -- 0      0      0      0      64     4      14     0      0      0      0      0
		   12288-16383    -- 0      0      0      0      2      2      0      0      0      0      0      0
		   16384-20479    -- 0      0      0      0      1      2      10     0      0      0      0      0
		   20480-24575    -- 0      0      0      0      0      3      0      0      0      0      0      0
		   24576-28671    -- 0      0      0      0      1      0      0      0      0      0      0      0
		   32768-36863    -- 0      0      0      0      0      0      6      0      0      0      0      0
		   45056-49151    -- 0      0      0      0      0      1      0      0      0      0      0      0
		   57344-61439    -- 0      0      0      0      0      0      13     0      0      0      0      0
		   65536-69631    -- 0      0      0      0      11     0      4      0      0      0      0      0
		   90112-94207    -- 0      0      0      0      0      1      0      0      0      0      0      0
		  131072-135167   -- 0      0      0      0      0      0      4      0      0      0      0      0
		  139264-143359   -- 0      0      0      0      1      0      0      0      0      0      0      0
		  184320-188415   -- 0      0      0      0      0      1      0      0      0      0      0      0
		  368640-372735   -- 0      0      0      0      0      1      0      0      0      0      0      0
		  720896-724991   -- 0      0      0      0      1      0      0      0      0      0      0      0
		  737280-741375   -- 0      0      0      0      0      1      0      0      0      0      0      0
		 1474560-1478655  -- 0      0      0      0      0      1      0      0      0      0      0      0
		   >=2093056      -- 0      0      0      0      0      1      0      0      0      0      0      0

