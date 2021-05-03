#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <assert.h>

#include "mtcp_schedule.h"

#ifdef ENABLE_UCTX
#include "lthread.h"
#endif

inline void
YieldToStack(struct mtcp_thread_context* mtcp, int reason)
{
	assert(mtcp);

#ifdef ENABLE_UCTX
	lthread_yield();
#endif
}

inline void
YieldToApp(struct mtcp_thread_context* mtcp, int interrupt)
{
	assert(mtcp);

#ifdef ENABLE_UCTX
	lthread_yield();
#endif
}

