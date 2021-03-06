/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <inttypes.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/mman.h>

#include <rte_per_lcore.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <rte_common.h>

#include "lthread_api.h"
#include "lthread_int.h"
#include "lthread_mutex.h"
#include "lthread_sched.h"
#include "lthread_queue.h"
#include "lthread_objcache.h"

/*
 * Create a mutex
 */
int
lthread_mutex_init(char *name, struct lthread_mutex **mutex,
		   __rte_unused const struct lthread_mutexattr *attr)
{
	struct lthread_mutex *m;

	if (mutex == NULL)
		return POSIX_ERRNO(EINVAL);


	m = _lthread_objcache_alloc((THIS_SCHED)->mutex_cache);
	if (m == NULL)
		return POSIX_ERRNO(EAGAIN);

	m->blocked = _lthread_queue_create("blocked queue");
	if (m->blocked == NULL) {
		_lthread_objcache_free((THIS_SCHED)->mutex_cache, m);
		return POSIX_ERRNO(EAGAIN);
	}

	if (name == NULL)
		strncpy(m->name, "no name", sizeof(m->name));
	else
		strncpy(m->name, name, sizeof(m->name));
	m->name[sizeof(m->name)-1] = 0;

	m->root_sched = THIS_SCHED;
	m->owner = NULL;

	rte_atomic64_init(&m->count);

	/* success */
	(*mutex) = m;
	return 0;
}

/*
 * Destroy a mutex
 */
int lthread_mutex_destroy(struct lthread_mutex *m)
{
	if ((m == NULL) || (m->blocked == NULL)) {
		return POSIX_ERRNO(EINVAL);
	}

	if (m->owner == NULL) {
		/* try to delete the blocked queue */
		if (_lthread_queue_destroy(m->blocked) < 0) {
			return POSIX_ERRNO(EBUSY);
		}

		/* free the mutex to cache */
		_lthread_objcache_free(m->root_sched->mutex_cache, m);
		return 0;
	}
	/* can't do its still in use */
	return POSIX_ERRNO(EBUSY);
}

/*
 * Try to obtain a mutex
 */
int lthread_mutex_lock(struct lthread_mutex *m)
{
	struct lthread *lt = THIS_LTHREAD;

	if ((m == NULL) || (m->blocked == NULL)) {
		return POSIX_ERRNO(EINVAL);
	}

	/* allow no recursion */
	if (m->owner == lt) {
		return POSIX_ERRNO(EDEADLK);
	}

	for (;;) {
		rte_atomic64_inc(&m->count);
		do {
			if (rte_atomic64_cmpset
			    ((uint64_t *) &m->owner, 0, (uint64_t) lt)) {
				/* happy days, we got the lock */
				return 0;
			}
			/* spin due to race with unlock when
			* nothing was blocked
			*/
		} while ((rte_atomic64_read(&m->count) == 1) &&
				(m->owner == NULL));

		/* queue the current thread in the blocked queue
		 * we defer this to after we return to the scheduler
		 * to ensure that the current thread context is saved
		 * before unlock could result in it being dequeued and
		 * resumed
		 */
		lt->pending_wr_queue = m->blocked;
		/* now relinquish cpu */
		_suspend();
		/* resumed, must loop and compete for the lock again */
	}
	return 0;
}

/* try to lock a mutex but dont block */
int lthread_mutex_trylock(struct lthread_mutex *m)
{
	struct lthread *lt = THIS_LTHREAD;

	if ((m == NULL) || (m->blocked == NULL)) {
		return POSIX_ERRNO(EINVAL);
	}

	if (m->owner == lt) {
		/* no recursion */
		return POSIX_ERRNO(EDEADLK);
	}

	rte_atomic64_inc(&m->count);
	if (rte_atomic64_cmpset
	    ((uint64_t *) &m->owner, (uint64_t) NULL, (uint64_t) lt)) {
		/* got the lock */
		return 0;
	}

	/* failed so return busy */
	rte_atomic64_dec(&m->count);
	return POSIX_ERRNO(EBUSY);
}

/*
 * Unlock a mutex
 */
int lthread_mutex_unlock(struct lthread_mutex *m)
{
	struct lthread *lt = THIS_LTHREAD;
	struct lthread *unblocked;

	if ((m == NULL) || (m->blocked == NULL)) {
		return POSIX_ERRNO(EINVAL);
	}

	/* fail if its owned */
	if (m->owner != lt || m->owner == NULL) {
		return POSIX_ERRNO(EPERM);
	}

	rte_atomic64_dec(&m->count);
	/* if there are blocked threads then make one ready */
	while (rte_atomic64_read(&m->count) > 0) {
		unblocked = _lthread_queue_remove(m->blocked);

		if (unblocked != NULL) {
			rte_atomic64_dec(&m->count);
			RTE_ASSERT(unblocked->sched != NULL);
			_ready_queue_insert((struct lthread_sched *)
					    unblocked->sched, unblocked);
			break;
		}
	}
	/* release the lock */
	m->owner = NULL;
	return 0;
}
