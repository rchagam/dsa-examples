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


#define ALLOC_SIZE (1024*1024)
#define MEMSET_PATTERN 'a'
#define ENQCMD_MAX_RETRIES 3

#define UMWAIT_DELAY 100000
/* C0.1 state */
#define UMWAIT_STATE 1

// Global variables 
__thread struct dsa_hw_desc thr_desc;
__thread struct dsa_completion_record thr_comp;

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

static __always_inline
int dsa_desc_submit(void *wq_portal, int dedicated, struct dsa_hw_desc *hw)
{
	/* printf("desc flags: 0x%x, opcode: 0x%x\n", hw->flags, hw->opcode); */
	if (dedicated) {
		movdir64b(hw, wq_portal);
		return 0;
	}
	else {
		for (int r = 0; r < ENQCMD_MAX_RETRIES; ++r) {
			if (!enqcmd(hw, wq_portal))
				return 0;
		}
		return 1;
	}
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
	
	// allocate memory
	void *src_addr = calloc(ALLOC_SIZE, sizeof(uint8_t));
	if (src_addr == NULL) {
		printf("Memory allocation error for size: 0x%x, error: %s\n", (uint32_t) ALLOC_SIZE, strerror(errno));
		return 1;
	}

	void *ref_addr = calloc(ALLOC_SIZE, sizeof(uint8_t));
	if (ref_addr == NULL) {
		printf("Memory allocation error for size: 0x%x, error: %s\n", (uint32_t) ALLOC_SIZE, strerror(errno));
		return 1;
	}
	memset(ref_addr, MEMSET_PATTERN, ALLOC_SIZE);

	struct dsa_hw_desc *desc;
	struct dsa_completion_record *comp;

	//desc = (struct dsa_hw_desc *) calloc(1, sizeof(struct dsa_hw_desc));
	//comp = (struct dsa_completion_record *) calloc(1, sizeof(struct dsa_completion_record));
	desc = &thr_desc;
	comp = &thr_comp;
	memset(desc, 0, sizeof(*desc));
	memset(comp, 0, sizeof(*comp));

	if (desc == NULL || comp == NULL) {
		printf("out of memory\n");
		return 1;
	}
	
	// memset pattern size is always bytes
	uint64_t memset_pattern;
	for (int i=0; i < 8; ++i)
		((uint8_t *) &memset_pattern)[i] = (uint8_t) MEMSET_PATTERN;

	// open DSA WQ
	int wq_fd = open(wq_path, O_RDWR);
	if (wq_fd < 0) {
		printf("DSA WQ %s open error: %s\n", wq_path, strerror(errno));
		return 1;
	}

	// map DSA WQ portal
	void *wq_portal = mmap(NULL, 0x1000, PROT_WRITE, MAP_SHARED | MAP_POPULATE, wq_fd, 0);
	if (wq_portal == NULL) {
		printf("mmap error for DSA wq: %s, error: %s\n", wq_path, strerror(errno));
		return 1;
	}

	// test memfill
	desc->opcode = DSA_OPCODE_MEMFILL;
	desc->flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_BOF | IDXD_OP_FLAG_RCR;
	desc->completion_addr =	(uint64_t) comp;
	desc->pattern = memset_pattern;
	desc->dst_addr = (uint64_t) src_addr;
	desc->xfer_size = (uint32_t) ALLOC_SIZE;

	// submit command
	dsa_desc_submit(wq_portal, wq_dedicated, desc);
	dsa_wait_busy_poll(&comp->status);
	
	// check status
	if (comp->status != DSA_COMP_SUCCESS)
		printf("DSA opcode: 0x%x failed with error code: 0x%x\n", desc->opcode, comp->status);
	else
		printf("DSA opcode: 0x%x completed successfully.\n", desc->opcode, comp->bytes_completed);
	
	if (memcmp(src_addr, ref_addr, ALLOC_SIZE) != 0) {
		printf("memcmp failed for dsa fill\n");
	}

	// cleanup heap
	free(src_addr);

	// unmap and close wq portal
	munmap(wq_portal, 0x1000);
	close(wq_fd);
}
