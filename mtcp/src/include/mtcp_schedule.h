#ifndef MTCP_SCHEDULE_H
#define MTCP_SCHEDULE_H

#include "mtcp.h"

/* global constants */
#define YIELD_REASON_TIMER          0x1
#define YIELD_REASON_EPOLL          0x2
#define YIELD_REASON_BLOCK          0x4

/* yield between stack context and app context */
inline void
YieldToStack(mtcp_thread_context_t mtcp, int reason);

inline void
YieldToApp(mtcp_thread_context_t mtcp, int interrupt);

#endif /* MTCP_SCHEDULE_H */
