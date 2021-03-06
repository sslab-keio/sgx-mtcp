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


#ifndef LTHREAD_TIMER_H_
#define LTHREAD_TIMER_H_

#include "lthread_int.h"
#include "lthread_sched.h"

// WARNING: Timer functions should be ported to sgx
#ifdef COMPILE_WITH_INTEL_SGX
#include "enclaveshim_ocalls.h"
#else
#define wrapper_rte_lcore_id() rte_lcore_id()
#endif


static inline uint64_t
_ns_to_clks(uint64_t ns)
{
#ifdef COMPILE_WITH_INTEL_SGX
	return 0;
#else
	unsigned __int128 clkns = rte_get_tsc_hz();

	clkns *= ns;
	clkns /= 1000000000;
	return (uint64_t) clkns;
#endif
}


static inline void
_timer_start(struct lthread *lt, uint64_t clks)
{
#ifndef COMPILE_WITH_INTEL_SGX
	if (clks > 0) {
		rte_timer_init(&lt->tim);
		rte_timer_reset(&lt->tim,
				clks,
				SINGLE,
				wrapper_rte_lcore_id(),
				_sched_timer_cb,
				(void *)lt);
	}
#endif
}


static inline void
_timer_stop(struct lthread *lt)
{
#ifndef COMPILE_WITH_INTEL_SGX
	if (lt != NULL) {
		rte_timer_stop(&lt->tim);
	}
#endif
}


#endif /* LTHREAD_TIMER_H_ */
