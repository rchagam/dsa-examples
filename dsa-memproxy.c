// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Intel Corporation. All rights reserved. */

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <linux/idxd.h>
#include <x86intrin.h>
#include <threads.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <execinfo.h>
#include <dlfcn.h>
#include <accel-config/libaccel_config.h>

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#define ENQCMD_MAX_RETRIES 3

#define UMWAIT_DELAY 100000
/* C0.1 state */
#define UMWAIT_STATE 1

#define USE_ORIG_FUNC(n) (use_std_lib_calls == 1 || n < dsa_min_size)
#define TS_NS(s, e) (((e.tv_sec*1000000000) + e.tv_nsec) - ((s.tv_sec*1000000000) + s.tv_nsec))

// thread specific variables
__thread struct dsa_hw_desc thr_desc __attribute__ ((aligned (32)));
__thread struct dsa_completion_record thr_comp __attribute__ ((aligned (32)));

// orignal std memory functions
void * (*orig_memset)(void *s, int c, size_t n) = NULL;
void * (*orig_memcpy)(void *dest, const void *src, size_t n) = NULL;
void * (*orig_memmove)(void *dest, const void *src, size_t n) = NULL;
int (*orig_memcmp)(const void *s1, const void *s2, size_t n) = NULL;

// global workqueue variables
struct accfg_ctx *memproxy_ctx;
struct accfg_wq *memproxy_wq;
uint64_t dsa_gencap;
int wq_size;
uint8_t dsa_initialized = 0;
uint8_t use_std_lib_calls = 0;
char wq_path[PATH_MAX];
int wq_dedicated = 0;
int wq_fd = 0;
void *wq_portal = NULL;
size_t dsa_min_size = 4096;

enum memop {
	MEMSET = 0x0,
	MEMCOPY,
	MEMMOVE,
	MEMCMP,
	MAX_MEMOP,
};

static const char* memop_names[] = {
	[MEMSET] = "set",
	[MEMCOPY] = "cpy",
	[MEMMOVE] = "mov",
	[MEMCMP] = "cmp"
};

// memory stats
#define HIST_BUCKET_SIZE 4096
#define HIST_NO_BUCKETS 512
enum stat_group {
	STDC_CALL = 0x0,
	DSA_CALL_SUCCESS,
	DSA_CALL_FAILED,
	MAX_STAT_GROUP
};

static const char* stat_group_names[] = {
	[STDC_CALL] = "stdc calls",
	[DSA_CALL_SUCCESS] = "dsa (success)",
	[DSA_CALL_FAILED] = "dsa (failed)"
};

int collect_stats = 1;
atomic_int op_counter[HIST_NO_BUCKETS][MAX_STAT_GROUP][MAX_MEMOP];
atomic_ullong lat_counter[HIST_NO_BUCKETS][MAX_STAT_GROUP][MAX_MEMOP];

// call initialize/cleanup functions when library is loaded
static void init_mem_proxy() __attribute__((constructor));
static void cleanup_mem_proxy() __attribute__((destructor));

static __always_inline inline void dump_desc(struct dsa_hw_desc *hw)
{
	struct dsa_raw_desc *rhw = (struct dsa_raw_desc *)hw;
	int i;

	printf("desc addr: %p\n", hw);

	for (i = 0; i < 8; i++)
		printf("desc[%d]: 0x%016lx\n", i, rhw->field[i]);
}

static __always_inline inline unsigned char enqcmd(struct dsa_hw_desc *desc, volatile void *reg)
{
	unsigned char retry;

	asm volatile(".byte 0xf2, 0x0f, 0x38, 0xf8, 0x02\t\n"
			"setz %0\t\n"
			: "=r"(retry) : "a" (reg), "d" (desc));
	return retry;
}

static __always_inline inline void movdir64b(struct dsa_hw_desc *desc, volatile void *reg)
{
	asm volatile(".byte 0x66, 0x0f, 0x38, 0xf8, 0x02\t\n"
		: : "a" (reg), "d" (desc));
}

static __always_inline inline void umonitor(const volatile void *addr)
{
	asm volatile(".byte 0xf3, 0x48, 0x0f, 0xae, 0xf0" : : "a"(addr));
}

static __always_inline inline int umwait(unsigned long timeout, unsigned int state)
{
	uint8_t r;
	uint32_t timeout_low = (uint32_t)timeout;
	uint32_t timeout_high = (uint32_t)(timeout >> 32);

	asm volatile(".byte 0xf2, 0x48, 0x0f, 0xae, 0xf1\t\n"
		"setc %0\t\n"
		: "=r"(r)
		: "c"(state), "a"(timeout_low), "d"(timeout_high));
	return r;
}

static __always_inline void dsa_wait_busy_poll(const volatile uint8_t *comp)
{
  while (*comp == 0) {
      _mm_pause();
  }
}

static __always_inline void dsa_wait_umwait(const volatile uint8_t* comp)
{
    while (*comp == 0) {

		umonitor(comp);

		// Hardware never writes 0 to this field. Software should initialize this field to 0 
		// so it can detect when the completion record has been written
		if (*comp == 0) {
			uint64_t delay = __rdtsc() + UMWAIT_DELAY;
			umwait(delay, UMWAIT_STATE);
		}
    }
}

static __always_inline int dsa_execute(void *wq_portal, int dedicated, 
	struct dsa_hw_desc *hw, volatile uint8_t* comp)
{
	//printf("desc flags: 0x%x, opcode: 0x%x, dedicated: %d\n", hw->flags, hw->opcode, dedicated);
	for (int r = 0; r < ENQCMD_MAX_RETRIES; ++r) {
		int retry = 0;
		*comp = 0;
		if (dedicated)
			movdir64b(hw, wq_portal);
		else
			retry = enqcmd(hw, wq_portal);
		if (!retry) {
			dsa_wait_busy_poll(comp);
			if (*comp == DSA_COMP_SUCCESS)
				return 0;	
			else
				return 1;
		}
	}
	return 1;
}

static void update_stats(int op, size_t n, uint64_t elapsed_ns, int group)
{
	if (unlikely(!collect_stats))
		return;
	int bucket = (n / HIST_BUCKET_SIZE);
	if (bucket >= HIST_NO_BUCKETS)  /* last bucket includes remaining sizes */
		bucket = HIST_NO_BUCKETS-1;
	++op_counter[bucket][group][op];
	lat_counter[bucket][group][op] += elapsed_ns;
}

static void print_stats()
{
	if (unlikely(!collect_stats))
		return;

	for (int t=0; t < 2; ++t) {
		if (t == 0)
			printf("\n******** Number of Memory Operations ********\n");
		else
			printf("\n******** Average Memory Operation Latency (ms)  ********\n");
			
		printf("%17s    ", "");
		for (int g = 0; g < MAX_STAT_GROUP; ++g)
			printf("<***** %-13s *****> ", stat_group_names[g]);
		printf("\n");

		printf("%-17s -- ", "Byte Range");
		for (int g = 0; g < MAX_STAT_GROUP; ++g) {
			for (int o = 0; o < MAX_MEMOP; ++o)
				printf("%-6s ", memop_names[o]);
		}
		printf("\n");

		for (int b = 0; b < HIST_NO_BUCKETS; ++b) {
			bool empty = true;
			for (int g = 0; g < MAX_STAT_GROUP; ++g) {
				for (int o = 0; o < MAX_MEMOP; ++o) {
					if (op_counter[b][g][o] != 0) {
						empty = false;
						break;
					}
				}
				if (!empty)
					break;
			}
			if (!empty) {	
				if (b < (HIST_NO_BUCKETS-1))
					printf("% 8d-%-8d -- ", b*4096, ((b+1)*4096)-1);
				else
					printf("   >=%-12d -- ", b*4096);
					
				for (int g = 0; g < MAX_STAT_GROUP; ++g) {
					for (int o = 0; o < MAX_MEMOP; ++o) {
						if (t == 0) {
							printf("%-6d ", op_counter[b][g][o]);
						}
						else {
							if (op_counter[b][g][o] != 0) {
								double avg_ms = ((double) lat_counter[b][g][o])/(((double) op_counter[b][g][o]) * 1000000.0);
								printf("%-6.2f ", avg_ms);
							}
							else {
								printf("%-6d ", 0);
							}
						}
					}
				}
				if (t == 0)
					for (int o = 1; o < MAX_FAILURES; ++o)
						printf("%-6d ", fail_counter[b][o]);
				printf("\n");
			}
		}
	}
}

void memproxy_init(void)
{
        unsigned int unused[2];
        unsigned int leaf, waitpkg;
	int dev_id = -1, shared = 1;

        struct accfg_device *device;
        struct accfg_wq *wq;
        int rc;

        /* detect umwait support */
        leaf = 7;
        waitpkg = 0;
        cpuid(&leaf, unused, &waitpkg, unused + 1);
        if (waitpkg & 0x20) {
                printf("umwait supported\n");
                umwait_support = 1;
        }

	memproxy_ctx = NULL;
	memproxy_wq = NULL;

	rc = accfg_new(&memproxy_ctx);
	if (rc < 0)
		return;

again:
        accfg_device_foreach(memproxy_ctx, device) {
                enum accfg_device_state dstate;

                /* Make sure that the device is enabled */
                dstate = accfg_device_get_state(device);
                if (dstate != ACCFG_DEVICE_ENABLED)
                        continue;

                /* Match the device to the id requested */
                if (accfg_device_get_id(device) != dev_id &&
                    dev_id != -1)
                        continue;

                accfg_wq_foreach(device, wq) {
                        enum accfg_wq_state wstate;
                        enum accfg_wq_mode mode;
                        enum accfg_wq_type type;

                        /* Get a workqueue that's enabled */
                        wstate = accfg_wq_get_state(wq);
                        if (wstate != ACCFG_WQ_ENABLED)
                                continue;

                        /* The wq type should be user */
                        type = accfg_wq_get_type(wq);
                        if (type != ACCFG_WQT_USER)
                                continue;

                        /* Make sure the mode is correct */
                        mode = accfg_wq_get_mode(wq);
                        if ((mode == ACCFG_WQ_SHARED && !shared) ||
                            (mode == ACCFG_WQ_DEDICATED && shared))
                                continue;

			if (mode == ACCFG_WQ_SHARED)
				wq_dedicated = false;
			else
				wq_dedicated = true;

			wq_size = accfg_wq_get_size(wq);

                        memproxy_wq = wq;
			break;
                }
		if (memproxy_wq) {
			dsa_gencap = accfg_device_get_gen_cap(device);
			break;
		}
        }

	// If we can't find an SWQ, try to find a DWQ
	if (memproxy_wq == NULL && shared == 1) {
		shared = 0;
		goto again;
	}

       if (memproxy_wq == NULL)
	      goto fail;

        rc = accfg_wq_get_user_dev_path(memproxy_wq, wq_path, PATH_MAX);
        if (rc) {
                printf("Error getting device path\n");
                goto fail;
        }

	// open DSA WQ
	wq_fd = open(wq_path, O_RDWR);
	if (wq_fd < 0) {
		printf("DSA WQ %s open error: %s\n", wq_path, strerror(errno));
		goto fail;
	}

	// map DSA WQ portal
	wq_portal = mmap(NULL, 0x1000, PROT_WRITE, MAP_SHARED | MAP_POPULATE, wq_fd, 0);
	if (wq_portal == NULL) {
		printf("mmap error for DSA wq: %s, error: %s\n", wq_path, strerror(errno));
		close(wq_fd);
		goto fail;
	}
	printf("*** initialized dsa ***\n");

        return;

fail:
	accfg_unref(memproxy_ctx);
	memproxy_ctx = NULL;
}

static void init_mem_proxy(void)
{
	uint8_t init_notcomplete = 0;

	if (atomic_compare_exchange_strong(&dsa_initialized, &init_notcomplete, 1)) {

		// save std c lib function pointers
		orig_memset = dlsym(RTLD_NEXT, "memset");
		orig_memcpy = dlsym(RTLD_NEXT, "memcpy");
		orig_memmove = dlsym(RTLD_NEXT, "memmove");
		orig_memcmp = dlsym(RTLD_NEXT, "memcmp");

               char *env_str = getenv("USESTDC_CALLS");
               if (env_str != NULL)
                       use_std_lib_calls = atoi(env_str);

		env_str = getenv("COLLECT_STATS");
		if (env_str != NULL)
			collect_stats = atoi(env_str);

		// initialize DSA 
		if (!use_std_lib_calls) {
			memproxy_init();

			if (memproxy_ctx == NULL) {
				use_std_lib_calls = 1;
				return;
			}
			// check environment variables
			char *dsa_min_size_str = getenv("DSA_MIN_BYTES");
			if (dsa_min_size_str != NULL) 
				dsa_min_size = atoi(dsa_min_size_str);

			printf("wq_dedicated: %d, wq_size: %d, dsa_cap: %lx, collect_stats: %d, "
				"use_std_lib_calls: %d, dsa_min_size: %d, wq_path: %s\n",
			wq_dedicated, wq_size, dsa_gencap, collect_stats, use_std_lib_calls, dsa_min_size, wq_path);
		}
	}
}

static void cleanup_mem_proxy(void)
{
	// unmap and close wq portal
	if (wq_portal != NULL) {
		munmap(wq_portal, 0x1000);
		close(wq_fd);
	}
	print_stats();
}

static void *dsa_memset(void *s, int c, size_t n, int *result)
{
	// memset pattern size is always bytes
	uint64_t memset_pattern;
	for (int i=0; i < 8; ++i)
		((uint8_t *) &memset_pattern)[i] = (uint8_t) c;

	// prepare memfill descriptor
	thr_desc.opcode = DSA_OPCODE_MEMFILL;
	thr_desc.flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_BOF | IDXD_OP_FLAG_RCR;
	thr_desc.completion_addr =	(uint64_t) &thr_comp;
	thr_desc.pattern = memset_pattern;
	thr_desc.dst_addr = (uint64_t) s;
	thr_desc.xfer_size = (uint32_t) n;

	*result = dsa_execute(wq_portal, wq_dedicated, &thr_desc, &thr_comp.status);
	return s;
}

static void *dsa_memcpymove(void *dest, const void *src, size_t n, bool is_memcpy, int *result)
{
	// prepare memfill descriptor
	thr_desc.opcode = DSA_OPCODE_MEMMOVE;
	thr_desc.flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_BOF | IDXD_OP_FLAG_RCR;
	thr_desc.completion_addr =	(uint64_t) &thr_comp;
	thr_desc.src_addr = (uint64_t) src;
	thr_desc.dst_addr = (uint64_t) dest;
	thr_desc.xfer_size = (uint32_t) n;

	*result = dsa_execute(wq_portal, wq_dedicated, &thr_desc, &thr_comp.status);
	return dest;
}

static int dsa_memcmp(const void *s1, const void *s2, size_t n, int *result)
{
	// prepare memfill descriptor
	thr_desc.opcode = DSA_OPCODE_COMPARE;
	thr_desc.flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_BOF | IDXD_OP_FLAG_RCR;
	thr_desc.completion_addr =	(uint64_t) &thr_comp;
	thr_desc.src_addr = (uint64_t) s1;
	thr_desc.src2_addr = (uint64_t) s2;
	thr_desc.xfer_size = (uint32_t) n;

	*result = dsa_execute(wq_portal, wq_dedicated, &thr_desc, &thr_comp.status);
	return thr_comp.result;
}

static void *mem_op_internal(int op, void *s1, const void *s2, size_t n, int c)
{
	int result = 0; /* 0 is success */
	void *ret = NULL;
	int use_orig_func = USE_ORIG_FUNC(n);
	struct timespec st, et;
	unsigned int t;

	if (unlikely(dsa_initialized == 0))
		init_mem_proxy();

	if (!use_orig_func) {
		if (collect_stats)
			clock_gettime(CLOCK_BOOTTIME, &st);

		switch (op) {
			case MEMSET: 
				ret = dsa_memset(s1, c, n, &result);
				break;
			case MEMCOPY:
				ret = dsa_memcpymove(s1, s2, n, 1, &result);
				break;
			case MEMMOVE:
				ret = dsa_memcpymove(s1, s2, n, 0, &result);
				break;
			case MEMCMP:
				ret = (void *) (uintptr_t) dsa_memcmp(s1, s2, n, &result);
				break;
		}

		if (collect_stats)
			clock_gettime(CLOCK_BOOTTIME, &et);

		if (result) { /* fallback to std c lib call if there is failure */
			update_stats(op, n, collect_stats ? TS_NS(st, et) : 0, DSA_CALL_FAILED);
			use_orig_func = 1;
			result = 0;
		}
		else {
			update_stats(op, n, collect_stats ? TS_NS(st, et) : 0, DSA_CALL_SUCCESS);
		}
	}

	if (use_orig_func) {
		if (collect_stats)
			clock_gettime(CLOCK_REALTIME, &st);
		switch (op) {
			case MEMSET: 
				ret = orig_memset(s1, c, n);
				break;
			case MEMCOPY:
				ret = orig_memcpy(s1, s2, n);
				break;
			case MEMMOVE:
				ret = orig_memmove(s1, s2, n);
				break;
			case MEMCMP:
				ret = (void *) (uintptr_t) orig_memcmp(s1, s2, n);
				break;
		}
		if (collect_stats)
			clock_gettime(CLOCK_REALTIME, &et);
		update_stats(op, n, collect_stats ? TS_NS(st, et) : 0, STDC_CALL);
	}

	return ret;
}

void *memset(void *s, int c, size_t n)
{
	return mem_op_internal(MEMSET, s, NULL, n, c);
}

void *memcpy(void *dest, const void *src, size_t n)
{
	return mem_op_internal(MEMCOPY, dest, src, n, 0);
}

void *memmove(void *dest, const void *src, size_t n)
{
	return mem_op_internal(MEMMOVE, dest, src, n, 0);
}

int memcmp(const void *s1, const void *s2, size_t n)
{
	return (int) (uintptr_t) mem_op_internal(MEMCMP, (void *)s1, s2, n, 0);
}
