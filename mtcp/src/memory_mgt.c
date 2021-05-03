#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
#include "debug.h"
#include "memory_mgt.h"

#ifdef COMPILE_WITH_INTEL_SGX
#include "enclaveshim_ocalls.h"
#endif

#ifdef USE_MTCP_MEMPOOL
typedef struct tag_mem_chunk
{
    int mc_free_chunks;
    struct tag_mem_chunk *mc_next;
} mem_chunk;
typedef mem_chunk *mem_chunk_t;

typedef struct mem_pool
{
	u_char *mp_startptr;      /* start pointer */
	mem_chunk_t mp_freeptr;   /* pointer to the start memory chunk */
	int mp_free_chunks;       /* number of total free chunks */
	int mp_total_chunks;       /* number of total free chunks */
	int mp_chunk_size;        /* chunk size in bytes */
	int mp_type; // type == 1 => allocate the big chunck in untrusted memory
	
} mem_pool;
/*----------------------------------------------------------------------------*/

int starts_with(const char *restrict string, const char *restrict prefix) {
    while(*prefix) {
        if(*prefix++ != *string++) {
            return 0;
        }
    }
    return 1;
}

mem_pool * 
MPCreate(char* name, int chunk_size, size_t total_size) {
    mem_pool_t mp;
    int res;

    if (chunk_size < sizeof(mem_chunk)) {
        TRACE_ERROR("The chunk size should be larger than %lu. current: %d\n",
                    sizeof(mem_chunk), chunk_size);
        return NULL;
    }
    if (chunk_size % 4 != 0) {
        TRACE_ERROR("The chunk size should be multiply of 4!\n");
        return NULL;
    }

    //assert(chunk_size <= 2*1024*1024);

    if ((mp = calloc(1, sizeof(mem_pool))) == NULL) {
        perror("calloc failed");
        exit(0);
    }
    mp->mp_type = 0;
    mp->mp_chunk_size = chunk_size;
    mp->mp_free_chunks = ((total_size + (chunk_size - 1)) / chunk_size);
    mp->mp_total_chunks = mp->mp_free_chunks;
    total_size = chunk_size * ((size_t) mp->mp_free_chunks);

#ifdef COMPILE_WITH_INTEL_SGX
    if (starts_with(name, "rbm_pool_") || starts_with(name, "sbm_pool_")) {
        mp->mp_type = 1;
    }
#endif

    my_printf("%s(%s, %d, %lu) allocate outside enclave: %s.\n", __func__, name, chunk_size, total_size, (mp->mp_type == 1 ? "yes" : "no"));

    /* allocate the big memory chunk */
#ifdef COMPILE_WITH_INTEL_SGX
if (mp->mp_type == 1) {
    res = posix_memalign_on_pagesize((void **)&mp->mp_startptr, total_size);
} else {
    mp->mp_startptr = malloc(total_size);
    res = (mp->mp_startptr == NULL);
}
#else
    res = posix_memalign((void **)&mp->mp_startptr, getpagesize(), total_size);
#endif
    if (res != 0) {
        TRACE_ERROR("posix_memalign failed, size=%ld\n", total_size);
        assert(0);
        free(mp);
        return (NULL);
    }

#ifdef COMPILE_WITH_INTEL_SGX
    if (mp->mp_type == 1) {
#endif
        /* try mlock only for superuser */
        if (geteuid() == 0) {
            if (mlock(mp->mp_startptr, total_size) < 0) TRACE_ERROR("m_lock failed, size=%ld\n", total_size);
        }
#ifdef COMPILE_WITH_INTEL_SGX
    }
#endif

	mp->mp_freeptr = (mem_chunk_t)mp->mp_startptr;
	mp->mp_freeptr->mc_free_chunks = mp->mp_free_chunks;
	mp->mp_freeptr->mc_next = NULL;

	return mp;
}
/*----------------------------------------------------------------------------*/
void *
MPAllocateChunk(mem_pool_t mp)
{
	mem_chunk_t p = mp->mp_freeptr;
	
	if (mp->mp_free_chunks == 0) 
		return (NULL);
	assert(p->mc_free_chunks > 0);
	
	p->mc_free_chunks--;
	mp->mp_free_chunks--;
	if (p->mc_free_chunks) {
		/* move right by one chunk */
		mp->mp_freeptr = (mem_chunk_t)((u_char *)p + mp->mp_chunk_size);
		mp->mp_freeptr->mc_free_chunks = p->mc_free_chunks;
		mp->mp_freeptr->mc_next = p->mc_next;
	}
	else {
		mp->mp_freeptr = p->mc_next;
	}

	return p;
}
/*----------------------------------------------------------------------------*/
void
MPFreeChunk(mem_pool_t mp, void *p)
{
	mem_chunk_t mcp = (mem_chunk_t)p;

	//	assert((u_char*)p >= mp->mp_startptr && 
	//		   (u_char *)p < mp->mp_startptr + mp->mp_total_size);
	assert(((u_char *)p - mp->mp_startptr) % mp->mp_chunk_size == 0);
	//	assert(*((u_char *)p + (mp->mp_chunk_size-1)) == 'a');
	//	*((u_char *)p + (mp->mp_chunk_size-1)) = 'f';
	
	mcp->mc_free_chunks = 1;
	mcp->mc_next = mp->mp_freeptr;
	mp->mp_freeptr = mcp;
	mp->mp_free_chunks++;
}
/*----------------------------------------------------------------------------*/
void
MPDestroy(mem_pool_t mp)
{
#ifdef COMPILE_WITH_INTEL_SGX
	if (mp->mp_type == 1) {
	    untrusted_free(mp->mp_startptr);
	} else {
#endif
        free(mp->mp_startptr);
#ifdef COMPILE_WITH_INTEL_SGX
    }
#endif
	free(mp);
}
/*----------------------------------------------------------------------------*/
int
MPGetFreeChunks(mem_pool_t mp)
{
	return mp->mp_free_chunks;
}
/*----------------------------------------------------------------------------*/
uint32_t 
MPIsDanger(mem_pool_t mp)
{
#define DANGER_THRESHOLD 0.95
#define SAFE_THRESHOLD 0.90
	uint32_t danger_num = mp->mp_total_chunks * DANGER_THRESHOLD;
	uint32_t safe_num = mp->mp_total_chunks * SAFE_THRESHOLD;
	if (danger_num < mp->mp_total_chunks - mp->mp_free_chunks) {
		return mp->mp_total_chunks - mp->mp_free_chunks - safe_num;
	}
	return 0;
}
/*----------------------------------------------------------------------------*/
uint32_t
MPIsOverSafeline(mem_pool_t mp)
{
#define SAFELINE 0.90
	uint32_t safe_num = mp->mp_total_chunks * SAFELINE;
	if (safe_num < mp->mp_total_chunks - mp->mp_free_chunks) {
		return 1;
	}
	return 0;
}
/*----------------------------------------------------------------------------*/
#else
/*----------------------------------------------------------------------------*/
mem_pool_t
MPCreate(char *name, int chunk_size, size_t total_size)
{
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_MPCreate(name, chunk_size, total_size);
#else
	struct rte_mempool *mp;
	size_t sz, items;
	
	items = total_size/chunk_size;
	sz = RTE_ALIGN_CEIL(chunk_size, RTE_CACHE_LINE_SIZE);
	mp = rte_mempool_create(name, items, sz, 0, 0, NULL,
				0, NULL, 0, rte_socket_id(),
				MEMPOOL_F_NO_SPREAD);

	if (mp == NULL) {
		TRACE_ERROR("Can't allocate memory for mempool!\n");
		exit(EXIT_FAILURE);
	}

	return mp;
#endif
}
/*----------------------------------------------------------------------------*/
void *
MPAllocateChunk(mem_pool_t mp)
{
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_MPAllocateChunk(mp);
#else
	int rc;
	void *buf;

	rc = rte_mempool_get(mp, (void **)&buf);
	if (rc != 0)
		return NULL;

	return buf;
#endif
}
/*----------------------------------------------------------------------------*/
void
MPFreeChunk(mem_pool_t mp, void *p)
{
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_MPFreeChunk(mp, p);
#else
	rte_mempool_put(mp, p);
#endif
}
/*----------------------------------------------------------------------------*/
void
MPDestroy(mem_pool_t mp)
{
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_MPDestroy(mp);
#else
#if RTE_VERSION < RTE_VERSION_NUM(16, 7, 0, 0)
	/* do nothing.. old versions don't have a method to reclaim back mem */
#else
	rte_mempool_free(mp);
#endif
#endif
}
/*----------------------------------------------------------------------------*/
int
MPGetFreeChunks(mem_pool_t mp)
{
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_MPGetFreeChunks(mp);
#else
#if RTE_VERSION <= RTE_VERSION_NUM(16, 7, 0, 0)
	return (int)rte_mempool_free_count(mp);
#else
	return (int)rte_mempool_avail_count(mp);
#endif
#endif
}
/*----------------------------------------------------------------------------*/
#endif
