#ifndef __DEBUG_H_
#define __DEBUG_H_

#include <errno.h>
#include <stdio.h>
#include <assert.h>


#ifdef COMPILE_WITH_INTEL_SGX
#include "enclaveshim_ocalls.h"
#else
#define my_printf(format, ...) printf(format, ##__VA_ARGS__)
#define my_fprintf(stream, format, ...) fprintf(stream, format, ##__VA_ARGS__)
#endif

#define TRACE_CONFIG(f, m...) my_fprintf(stdout, f, ##m)

#ifdef DBGERR

#define TRACE_ERROR(f, m...) { \
	my_fprintf(stdout, "[%10s:%4d] " f, __FUNCTION__, __LINE__, ##m);	\
	}

#else

#define TRACE_ERROR(f, m...)	(void)0

#endif /* DBGERR */

#ifdef DBGMSG

#define TRACE_DBG(f, m...) {\
	my_fprintf(stderr, "[%10s:%4d] " \
			f, __FUNCTION__, __LINE__, ##m);   \
	}

#else

#define TRACE_DBG(f, m...)   (void)0

#endif /* DBGMSG */

#ifdef INFO                       

#define TRACE_INFO(f, m...) {                                         \
	my_fprintf(stdout, "[%10s:%4d] " f,__FUNCTION__, __LINE__, ##m);    \
    }

#else

#define TRACE_INFO(f, m...) (void)0

#endif /* INFO */

#ifdef EPOLL
#define TRACE_EPOLL(f, m...) TRACE_FUNC("EPOLL", f, ##m)
#else
#define TRACE_EPOLL(f, m...)   (void)0
#endif

#ifdef APP
#define TRACE_APP(f, m...) TRACE_FUNC("APP", f, ##m)
#else
#define TRACE_APP(f, m...) (void)0
#endif

#ifdef DBGFUNC

#define TRACE_FUNC(n, f, m...) {                                         \
	my_fprintf(stdout, "%6s: %10s:%4d] " \
			f, n, __FUNCTION__, __LINE__, ##m);    \
	}

#else

#define TRACE_FUNC(f, m...) (void)0

#endif /* DBGFUNC */

#endif /* __DEBUG_H_ */
