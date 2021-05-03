#ifndef EVENTPOLL_H
#define EVENTPOLL_H

#include "mtcp_api.h"
#include "mtcp_epoll.h"

#include "thread_wrapper.h"

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

#define SPIN_BEFORE_SLEEP FALSE

/*----------------------------------------------------------------------------*/
struct mtcp_epoll_stat
{
	uint64_t calls;
	uint64_t waits;
	uint64_t wakes;

	uint64_t issued;
	uint64_t registered;
	uint64_t invalidated;
	uint64_t handled;
};
/*----------------------------------------------------------------------------*/
struct mtcp_epoll_event_int
{
	struct mtcp_epoll_event ev;
	int sockid;
};
/*----------------------------------------------------------------------------*/
enum event_queue_type
{
	USR_EVENT_QUEUE = 0, 
	USR_SHADOW_EVENT_QUEUE = 1, 
	MTCP_EVENT_QUEUE = 2
};
/*----------------------------------------------------------------------------*/
struct event_queue
{
	struct mtcp_epoll_event_int *events;
	int start;			// starting index
	int end;			// ending index
	
	int size;			// max size
	int num_events;		// number of events
};
/*----------------------------------------------------------------------------*/
struct mtcp_epoll
{
	struct event_queue *usr_queue;
	struct event_queue *usr_shadow_queue;
	struct event_queue *mtcp_queue;

	uint8_t waiting;
	struct mtcp_epoll_stat stat;
	
	thread_cond_t epoll_cond;
	thread_mutex_t epoll_lock;
};
/*----------------------------------------------------------------------------*/

int 
CloseEpollSocket(mctx_t mctx, int epid);

#endif /* EVENTPOLL_H */
