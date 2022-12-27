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
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <execinfo.h>
#include <dlfcn.h>
#include <accel-config/libaccel_config.h>

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

// DSA capabilities
#define GENCAP_CC_MEMORY  0x4

#define ENQCMD_MAX_RETRIES 3

#define UMWAIT_DELAY 100000
/* C0.1 state */
#define UMWAIT_STATE 1

#define USE_ORIG_FUNC(n) (use_std_lib_calls == 1 || n < dsa_min_size)
#define TS_NS(s, e) (((e.tv_sec*1000000000) + e.tv_nsec) - ((s.tv_sec*1000000000) + s.tv_nsec))

#define MAX_WQS 4

// thread specific variables
__thread struct dsa_hw_desc thr_desc __attribute__ ((aligned (32)));
__thread struct dsa_completion_record thr_comp __attribute__ ((aligned (32)));

// orignal std memory functions
void * (*orig_memset)(void *s, int c, size_t n) = NULL;
void * (*orig_memcpy)(void *dest, const void *src, size_t n) = NULL;
void * (*orig_memmove)(void *dest, const void *src, size_t n) = NULL;
int (*orig_memcmp)(const void *s1, const void *s2, size_t n) = NULL;

struct memproxy_wq {
	struct accfg_wq *acc_wq;
	char wq_path[PATH_MAX];
	int dedicated;
	uint64_t dsa_gencap;
	int wq_size;
	int wq_fd;
	void *wq_portal;
	int dwq_desc_outstanding;

};

// global workqueue variables
struct accfg_ctx *memproxy_ctx;
struct memproxy_wq wqs[MAX_WQS];
uint8_t num_wqs;
uint8_t next_wq;
uint8_t dsa_initialized = 0;
uint8_t use_std_lib_calls = 0;
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
	DSA_FAIL_CODES,
	MAX_STAT_GROUP
};

static const char* stat_group_names[] = {
	[STDC_CALL] = "stdc calls",
	[DSA_CALL_SUCCESS] = "dsa (success)",
	[DSA_CALL_FAILED] = "dsa (failed)",
	[DSA_FAIL_CODES] = "failure reason"
};

enum return_code {
	SUCCESS = 0x0,
	RETRIES,
	PAGE_FAULT,
	FAIL_OTHERS,
	MAX_FAILURES,
};

static const char* failure_names[] = {
	[SUCCESS] = "Success",
	[RETRIES] = "Retries",
	[PAGE_FAULT] = "PFs",
	[FAIL_OTHERS] = "Others",
};

enum wait_options {
	WAIT_BUSYPOLL = 0,
	WAIT_UMWAIT,
	WAIT_YIELD
};

static const char* wait_names[] = {
	[WAIT_BUSYPOLL] = "busypoll",
	[WAIT_UMWAIT] = "umwait",
	[WAIT_YIELD] = "yield",
};

int wait_method = WAIT_BUSYPOLL;

int collect_stats = 1;
atomic_int op_counter[HIST_NO_BUCKETS][MAX_STAT_GROUP][MAX_MEMOP];
atomic_ullong bytes_counter[HIST_NO_BUCKETS][MAX_STAT_GROUP];
atomic_ullong lat_counter[HIST_NO_BUCKETS][MAX_STAT_GROUP][MAX_MEMOP];
atomic_int fail_counter[HIST_NO_BUCKETS][MAX_FAILURES];

// call initialize/cleanup functions when library is loaded
static void init_mem_proxy() __attribute__((constructor));
static void cleanup_mem_proxy() __attribute__((destructor));

static int umwait_support;

static inline void cpuid(unsigned int *eax, unsigned int *ebx,
                         unsigned int *ecx, unsigned int *edx)
{
        /* ecx is often an input as well as an output. */
        asm volatile("cpuid"
                : "=a" (*eax),
                "=b" (*ebx),
                "=c" (*ecx),
                "=d" (*edx)
                : "0" (*eax), "2" (*ecx)
                : "memory");
}

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

static __always_inline void dsa_wait_yield(const volatile uint8_t *comp)
{
  while (*comp == 0) {
      sched_yield();
  }
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

static __always_inline int dsa_execute(struct memproxy_wq *wq, 
	struct dsa_hw_desc *hw, volatile uint8_t* comp)
{
	//printf("desc flags: 0x%x, opcode: 0x%x, dedicated: %d\n", hw->flags, hw->opcode, dedicated);
	for (int r = 0; r < ENQCMD_MAX_RETRIES; ++r) {
		int retry = 0;
		*comp = 0;
		if (wq->dedicated) {
			int old_outstanding = wq->dwq_desc_outstanding;
			 if (old_outstanding < wq->wq_size &&
					atomic_compare_exchange_strong(
					&wq->dwq_desc_outstanding, &old_outstanding,
					old_outstanding+1))
				movdir64b(hw, wq->wq_portal);
			else {
				retry = 1;
			}
		} else {
			retry = enqcmd(hw, wq->wq_portal);
		}
		if (!retry) {
			if (wait_method == WAIT_YIELD)
				dsa_wait_yield(comp);
			else if (wait_method == WAIT_UMWAIT && umwait_support)
				dsa_wait_umwait(comp);
			else
				dsa_wait_busy_poll(comp);

			if (wq->dedicated)
				atomic_store(&wq->dwq_desc_outstanding, wq->dwq_desc_outstanding - 1);
			if (*comp == DSA_COMP_SUCCESS)
				return SUCCESS;
			else if ((*comp & 0x7F) == DSA_COMP_PAGE_FAULT_NOBOF)
				return PAGE_FAULT;
			else {
				printf("failed status %x xfersz %x\n", *comp, hw->xfer_size);
				return FAIL_OTHERS;
			}
		}
	}
	return RETRIES;
}

static void update_stats(int op, size_t n, uint64_t elapsed_ns, int group, int error_code)
{
	if (unlikely(!collect_stats))
		return;
	int bucket = (n / HIST_BUCKET_SIZE);
	if (bucket >= HIST_NO_BUCKETS)  /* last bucket includes remaining sizes */
		bucket = HIST_NO_BUCKETS-1;
	++op_counter[bucket][group][op];
	bytes_counter[bucket][group] += n;
	lat_counter[bucket][group][op] += elapsed_ns;
	if (group == DSA_CALL_FAILED)
		++fail_counter[bucket][error_code];

}

static void print_stats()
{
	if (unlikely(!collect_stats))
		return;

	for (int t=0; t < 2; ++t) {
		if (t == 0)
			printf("\n******** Number of Memory Operations ********\n");
		else
			printf("\n******** Average Memory Operation Latency (us)  ********\n");
			
		printf("%17s    ", "");
		for (int g = 0; g < MAX_STAT_GROUP; ++g)
			if (g == DSA_FAIL_CODES)
				printf("<***** %-13s *****> ", stat_group_names[g]);
			else
				printf("<*************** %-13s ***************> ", stat_group_names[g]);
		printf("\n");

		printf("%-17s -- ", "Byte Range");
		for (int g = 0; g < MAX_STAT_GROUP - 1; ++g) {
			for (int o = 0; o < MAX_MEMOP; ++o)
				printf("%-8s ", memop_names[o]);
			printf("%-12s ", "bytes");
		}
		if (t == 0)
			for (int o = 1; o < MAX_FAILURES; ++o)
				printf("%-6s ", failure_names[o]);
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
					
				for (int g = 0; g < MAX_STAT_GROUP - 1; ++g) {
					for (int o = 0; o < MAX_MEMOP; ++o) {
						if (t == 0) {
							printf("%-8d ", op_counter[b][g][o]);
						}
						else {
							if (op_counter[b][g][o] != 0) {
								double avg_us = ((double) lat_counter[b][g][o])/(((double) op_counter[b][g][o]) * 1000.0);
								printf("%-6.2f ", avg_us);
							}
							else {
								printf("%-6d ", 0);
							}
						}
					}
					if (t == 0)
						printf("%-12ld ", bytes_counter[b][g]);
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
	int used_devids[MAX_WQS];
        struct accfg_device *device;
        struct accfg_wq *wq;
        int rc;
	int i;

        /* detect umwait support */
        leaf = 7;
        waitpkg = 0;
        cpuid(&leaf, unused, &waitpkg, unused + 1);
        if (waitpkg & 0x20) {
                printf("umwait supported\n");
                umwait_support = 1;
        }

	memproxy_ctx = NULL;
	for (i = 0; i < MAX_WQS; i++) {
		wqs[i].acc_wq = NULL;
		used_devids[i] = -1;
	}

	rc = accfg_new(&memproxy_ctx);
	if (rc < 0)
		return;
	num_wqs = 0;

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

		/* Check if we have already used a wq on this device */
		for (i = 0; i < MAX_WQS; i++)
			if (accfg_device_get_id(device) == used_devids[i])
				break;
		if (i != MAX_WQS)
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
				wqs[num_wqs].dedicated = false;
			else
				wqs[num_wqs].dedicated = true;

			wqs[num_wqs].wq_size = accfg_wq_get_size(wq);

                        wqs[num_wqs].acc_wq = wq;
			wqs[num_wqs].dsa_gencap = accfg_device_get_gen_cap(device);

			used_devids[num_wqs] = accfg_device_get_id(device);

			num_wqs++;
			break;
                }
		if (num_wqs == MAX_WQS)
			break;
        }

	// If we can't find an SWQ, try to find a DWQ
	if (num_wqs < MAX_WQS && shared == 1) {
		shared = 0;
		goto again;
	}

       if (num_wqs == 0)
	      goto fail;

       for (i = 0; i < num_wqs; i++) {
	       struct accfg_wq *acc_wq = wqs[i].acc_wq;

		rc = accfg_wq_get_user_dev_path(acc_wq, wqs[i].wq_path, PATH_MAX);
		if (rc) {
			printf("Error getting device path\n");
			goto fail_wq;
		}

		// open DSA WQ
		wqs[i].wq_fd = open(wqs[i].wq_path, O_RDWR);
		if (wqs[i].wq_fd < 0) {
			printf("DSA WQ %s open error: %s\n", wqs[i].wq_path, strerror(errno));
			goto fail_wq;
		}

		// map DSA WQ portal
		wqs[i].wq_portal = mmap(NULL, 0x1000, PROT_WRITE, MAP_SHARED | MAP_POPULATE, wqs[i].wq_fd, 0);
		if (wqs[i].wq_portal == NULL) {
			printf("mmap error for DSA wq: %s, error: %s\n", wqs[i].wq_path, strerror(errno));
			close(wqs[i].wq_fd);
			goto fail_wq;
		}
       }
	printf("*** initialized dsa ***\n");

        return;

fail_wq:
	for (int j = 0; j < i; j++) {
		munmap(wqs[j].wq_portal, 0x1000);
		close(wqs[j].wq_fd);
	}
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

		env_str = getenv("WAIT_METHOD");
		if (env_str != NULL) {
			if (!strncmp(env_str, "yield", 5))
				wait_method = WAIT_YIELD;
			else if (!strncmp(env_str, "umwait", 6))
				wait_method = WAIT_UMWAIT;
		}

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

			for (int i = 0; i < num_wqs; i++)
				printf("[%d] wq_path: %s, dedicated: %d, wq_size: %d, dsa_cap: %lx\n", i, 
					wqs[i].wq_path, wqs[i].dedicated, wqs[i].wq_size, wqs[i].dsa_gencap);
			printf("collect_stats: %d, use_std_lib_calls: %d, dsa_min_size: %d, wait_method %s\n",
				collect_stats, use_std_lib_calls, dsa_min_size, wait_names[wait_method]);
		}
	}
}

static void cleanup_mem_proxy(void)
{
	// unmap and close wq portal
	for (int i = 0; i < num_wqs; i++) {
		if (wqs[i].wq_portal != NULL) {
			munmap(wqs[i].wq_portal, 0x1000);
			close(wqs[i].wq_fd);
		}
	}
	print_stats();
}

static struct memproxy_wq *get_wq(void)
{
	/* No need to have strict round robin wq usage
	 * in order to avoid using locked instructions */
	int wq_idx = next_wq++ % num_wqs;

	return &wqs[wq_idx];
}

static void *dsa_memset(void *s, int c, size_t n, int *result)
{
	// memset pattern size is always bytes
	uint64_t memset_pattern;
	struct memproxy_wq *wq = get_wq();

	for (int i=0; i < 8; ++i)
		((uint8_t *) &memset_pattern)[i] = (uint8_t) c;

	// prepare memfill descriptor
	thr_desc.opcode = DSA_OPCODE_MEMFILL;
	thr_desc.flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if (wq->dsa_gencap & GENCAP_CC_MEMORY)
		thr_desc.flags |= IDXD_OP_FLAG_CC;
	thr_desc.completion_addr =	(uint64_t) &thr_comp;
	thr_desc.pattern = memset_pattern;
	thr_desc.dst_addr = (uint64_t) s;
	thr_desc.xfer_size = (uint32_t) n;

	*result = dsa_execute(wq, &thr_desc, &thr_comp.status);
	return s;
}

static void *dsa_memcpymove(void *dest, const void *src, size_t n, bool is_memcpy, int *result)
{
	struct memproxy_wq *wq = get_wq();

	// prepare memfill descriptor
	thr_desc.opcode = DSA_OPCODE_MEMMOVE;
	thr_desc.flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if (wq->dsa_gencap & GENCAP_CC_MEMORY)
		thr_desc.flags |= IDXD_OP_FLAG_CC;
	thr_desc.completion_addr =	(uint64_t) &thr_comp;
	thr_desc.src_addr = (uint64_t) src;
	thr_desc.dst_addr = (uint64_t) dest;
	thr_desc.xfer_size = (uint32_t) n;

	*result = dsa_execute(wq, &thr_desc, &thr_comp.status);
	return dest;
}

static int dsa_memcmp(const void *s1, const void *s2, size_t n, int *result)
{
	struct memproxy_wq *wq = get_wq();

	// prepare memfill descriptor
	thr_desc.opcode = DSA_OPCODE_COMPARE;
	thr_desc.flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	thr_desc.completion_addr =	(uint64_t) &thr_comp;
	thr_desc.src_addr = (uint64_t) s1;
	thr_desc.src2_addr = (uint64_t) s2;
	thr_desc.xfer_size = (uint32_t) n;

	*result = dsa_execute(wq, &thr_desc, &thr_comp.status);
	return thr_comp.result;
}

static void *mem_op_internal(int op, void *s1, const void *s2, size_t n, int c)
{
	int result = 0;
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
			update_stats(op, n, collect_stats ? TS_NS(st, et) : 0, DSA_CALL_FAILED, result);
			use_orig_func = 1;
			result = 0;
		}
		else {
			update_stats(op, n, collect_stats ? TS_NS(st, et) : 0, DSA_CALL_SUCCESS, 0);
		}
	}

	if (use_orig_func) {
		if (collect_stats)
			clock_gettime(CLOCK_BOOTTIME, &st);
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
			clock_gettime(CLOCK_BOOTTIME, &et);
		update_stats(op, n, collect_stats ? TS_NS(st, et) : 0, STDC_CALL, 0);
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
