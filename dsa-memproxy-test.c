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

#define MAX_ITERS 10000
#define MAX_THREADS 10
#define LOG_COUNT 1000

atomic_int no_ops=0;

int thread_func(void *thr_data)
{
	for (int i=0; i < MAX_ITERS; ++i) {
		// allocate memory
		void *src_addr = calloc(ALLOC_SIZE, sizeof(uint8_t));
		void *dest_addr = calloc(ALLOC_SIZE, sizeof(uint8_t));

		memset(src_addr, 'T', ALLOC_SIZE);
		memcpy(dest_addr, src_addr, ALLOC_SIZE);
		
		if (memcmp(dest_addr, src_addr, ALLOC_SIZE) != 0)
			printf("memcmp failed for dsa fill\n");

		free(src_addr);
		free(dest_addr);
		++no_ops;
		if (no_ops % LOG_COUNT == 0)
			printf("completed %d ops\n", no_ops);
	}
}

int main(int argc, char **argv)
{
 	thrd_t threads[MAX_THREADS];
    for(int t = 0; t < MAX_THREADS; ++t)
        thrd_create(&threads[t], thread_func, NULL);
    for(int t = 0; t < MAX_THREADS; ++t)
        thrd_join(threads[t], NULL);
	
	printf("all threads completed execution\n");
	return 0;
}
