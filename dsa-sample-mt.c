// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Intel Corporation. All rights reserved. */

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

#define ALLOC_SIZE (1024*1024)
#define MEMSET_PATTERN 'a'
#define ENQCMD_MAX_RETRIES 3

#define UMWAIT_DELAY 100000
/* C0.1 state */
#define UMWAIT_STATE 1

#define MAX_ITERS 100000
#define MAX_THREADS 10
#define LOG_COUNT 10000

// Global variables 
__thread struct dsa_hw_desc thr_desc;
__thread struct dsa_completion_record thr_comp;
void *wq_portal = NULL;
int wq_fd = 0;
int wq_dedicated = 0;
atomic_int dsa_memset_ops, std_memset_ops;
atomic_int dsa_memcpy_ops, std_memcpy_ops;
atomic_int dsa_memmove_ops, std_memmove_ops;
atomic_int dsa_memcmp_ops, std_memcmp_ops;

static inline void dump_desc(struct dsa_hw_desc *hw)
{
	struct dsa_raw_desc *rhw = (struct dsa_raw_desc *)hw;
	int i;

	printf("desc addr: %p\n", hw);

	for (i = 0; i < 8; i++)
		printf("desc[%d]: 0x%016lx\n", i, rhw->field[i]);
}

static inline unsigned char enqcmd(struct dsa_hw_desc *desc, volatile void *reg)
{
	unsigned char retry;

	asm volatile(".byte 0xf2, 0x0f, 0x38, 0xf8, 0x02\t\n"
			"setz %0\t\n"
			: "=r"(retry) : "a" (reg), "d" (desc));
	return retry;
}

static inline void movdir64b(struct dsa_hw_desc *desc, volatile void *reg)
{
	asm volatile(".byte 0x66, 0x0f, 0x38, 0xf8, 0x02\t\n"
		: : "a" (reg), "d" (desc));
}

static inline void umonitor(const volatile void *addr)
{
	asm volatile(".byte 0xf3, 0x48, 0x0f, 0xae, 0xf0" : : "a"(addr));
}

static inline int umwait(unsigned long timeout, unsigned int state)
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

void dsa_wait_busy_poll(const volatile uint8_t *comp)
{
  while (*comp == 0) {
      _mm_pause();
  }
}

void dsa_wait_umwait(const volatile uint8_t* comp)
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
	/* printf("desc flags: 0x%x, opcode: 0x%x\n", hw->flags, hw->opcode); */
	if (dedicated) {
		movdir64b(hw, wq_portal);
		return 0;
	}
	else {
		*comp = 0;
		for (int r = 0; r < ENQCMD_MAX_RETRIES; ++r) {
			if (!enqcmd(hw, wq_portal)) {
				dsa_wait_busy_poll(comp);
				if (*comp == DSA_COMP_SUCCESS)
					return 0;	
				return 1;
			}
		}
		return 1;
	}
}


int init_dsa(const char *wq_path, int wq_dedicated)
{
	// open DSA WQ
	wq_fd = open(wq_path, O_RDWR);
	if (wq_fd < 0) {
		printf("DSA WQ %s open error: %s\n", wq_path, strerror(errno));
		return 1;
	}

	// map DSA WQ portal
	wq_portal = mmap(NULL, 0x1000, PROT_WRITE, MAP_SHARED | MAP_POPULATE, wq_fd, 0);
	if (wq_portal == NULL) {
		printf("mmap error for DSA wq: %s, error: %s\n", wq_path, strerror(errno));
		return 1;
	}

	return 0;
}

void cleanup_dsa(void)
{
	// unmap and close wq portal
	if (wq_portal != NULL) {
		munmap(wq_portal, 0x1000);
		close(wq_fd);
	}
	printf("dsa_memset_ops: %u, std_memset_ops: %u\n", dsa_memset_ops, std_memset_ops);
	printf("dsa_memcpy_ops: %u, std_memcpy_ops: %u\n", dsa_memcpy_ops, std_memcpy_ops);
	printf("dsa_memmove_ops: %u, std_memmove_ops: %u\n", dsa_memmove_ops, std_memmove_ops);
	printf("dsa_memcmp_ops: %u, std_memcmp_ops: %u\n", dsa_memcmp_ops, std_memcmp_ops);
}

#if 0
void *memcpy(void *dest, const void *src, size_t n)
int memcmp(const void *s1, const void *s2, size_t n);
void *memmove(void *dest, const void *src, size_t n);
#endif
void *dsa_memset(void *s, int c, size_t n)
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

	if (dsa_execute(wq_portal, wq_dedicated, &thr_desc, &thr_comp.status)) {
		++std_memset_ops;
		return memset(s, c, n);
	}
	else {
		++dsa_memset_ops;
		return s;
	}
}

void *dsa_memcpymove(void *dest, const void *src, size_t n, bool is_memcpy)
{
	// prepare memfill descriptor
	thr_desc.opcode = DSA_OPCODE_MEMMOVE;
	thr_desc.flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_BOF | IDXD_OP_FLAG_RCR;
	thr_desc.completion_addr =	(uint64_t) &thr_comp;
	thr_desc.src_addr = (uint64_t) src;
	thr_desc.dst_addr = (uint64_t) dest;
	thr_desc.xfer_size = (uint32_t) n;

	if (dsa_execute(wq_portal, wq_dedicated, &thr_desc, &thr_comp.status)) {
		if (is_memcpy) {
			++std_memcpy_ops;
			return memcpy(dest, src, n);
		}
		else {
			++std_memmove_ops;
			return memmove(dest, src, n);
		}
	}
	else {
		if (is_memcpy)
			++dsa_memcpy_ops;
		else
			++dsa_memmove_ops;
		return dest;
	}
}

int dsa_memcmp(const void *s1, const void *s2, size_t n)
{
	// prepare memfill descriptor
	thr_desc.opcode = DSA_OPCODE_COMPARE;
	thr_desc.flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_BOF | IDXD_OP_FLAG_RCR;
	thr_desc.completion_addr =	(uint64_t) &thr_comp;
	thr_desc.src_addr = (uint64_t) s1;
	thr_desc.src2_addr = (uint64_t) s2;
	thr_desc.xfer_size = (uint32_t) n;

	if (dsa_execute(wq_portal, wq_dedicated, &thr_desc, &thr_comp.status)) {
		++std_memcmp_ops;
		return memcmp(s1, s2, n);
	}
	else {
		++dsa_memcmp_ops;
		return thr_comp.result;
	}
}

int thread_func(void *thr_data)
{
	for (int i=0; i < MAX_ITERS; ++i) {
		// allocate memory
		void *src_addr = calloc(ALLOC_SIZE, sizeof(uint8_t));
		void *dest_addr = calloc(ALLOC_SIZE, sizeof(uint8_t));

		dsa_memset(src_addr, 'T', ALLOC_SIZE);
		dsa_memcpymove(dest_addr, src_addr, ALLOC_SIZE, 1);
		memset(src_addr, 'T', ALLOC_SIZE);
		
		if (memcmp(dest_addr, src_addr, ALLOC_SIZE) != 0)
			printf("memcmp failed for dsa fill\n");

		if (dsa_memcmp(dest_addr, src_addr, ALLOC_SIZE) != 0)
			printf("dsa memcmp failed for dsa fill\n");

		free(src_addr);
		free(dest_addr);
		if ((dsa_memset_ops % LOG_COUNT) == 0) 
			printf("dsa_memset_ops: %u\n", dsa_memset_ops);
	}
}

int main(int argc, char **argv)
{
	char *wq_path;
	int wq_dedicated;
	
	if (argc < 3) {
		printf("Usage: %s <wq path> <queue type - 1 (dedicated), 0 (shared)>\n", argv[0]);
		return 1;
	}

	wq_path = argv[1];
	wq_dedicated = atoi(argv[2]);
	
	// init dsa
	if(init_dsa(wq_path, wq_dedicated))
		goto cleanup;

 	thrd_t threads[MAX_THREADS];
    for(int t = 0; t < MAX_THREADS; ++t)
        thrd_create(&threads[t], thread_func, NULL);
    for(int t = 0; t < MAX_THREADS; ++t)
        thrd_join(threads[t], NULL);
	
	printf("all finished\n");
cleanup:
	// cleanup heap
	cleanup_dsa();

	return 0;
}
