#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <assert.h>
#include <limits.h>

#include <mtcp_api.h>
#include <mtcp_epoll.h>
#include "cpu.h"
#include "rss.h"
#include "http_parsing.h"
#include "netlib.h"
#include "debug.h"

#define HTTP_HEADER_LEN 1024
#define MAX_FLOW_NUM  10000
#define MAX_EVENTS (MAX_FLOW_NUM * 3)

#define IP_RANGE 1
#define MAX_IP_STR_LEN 16

#define BUF_SIZE (8*1024)

#ifndef MAX_CPUS
#define MAX_CPUS		16
#endif
/*----------------------------------------------------------------------------*/
static pthread_t app_thread[MAX_CPUS];
static mctx_t g_mctx[MAX_CPUS];
/*----------------------------------------------------------------------------*/
static int num_cores;
static int core_limit;
/*----------------------------------------------------------------------------*/
static char host[MAX_IP_STR_LEN + 1] = {'\0'};
static in_addr_t daddr;
static in_port_t dport;
static in_addr_t saddr;
/*----------------------------------------------------------------------------*/
struct thread_context
{
	int core;

	mctx_t mctx;
	int ep;

	int target;
	int started;
	int errors;
	int incompletes;
	int done;
	int pending;
};
typedef struct thread_context* thread_context_t;
/*----------------------------------------------------------------------------*/
struct wget_vars
{
	int request_sent;

	char response[HTTP_HEADER_LEN];
	int resp_len;
	int headerset;
	uint32_t header_len;
	uint64_t file_len;
	uint64_t recv;
	uint64_t write;

	struct timeval t_start;
	struct timeval t_end;
	
	int fd;
};
/*----------------------------------------------------------------------------*/
static struct thread_context *g_ctx[MAX_CPUS] = {0};
static struct wget_stat *g_stat[MAX_CPUS] = {0};
/*----------------------------------------------------------------------------*/
thread_context_t 
CreateContext(int core)
{
	thread_context_t ctx;

	ctx = (thread_context_t)calloc(1, sizeof(struct thread_context));
	if (!ctx) {
		perror("malloc");
		TRACE_ERROR("Failed to allocate memory for thread context.\n");
		return NULL;
	}
	ctx->core = core;

	ctx->mctx = mtcp_create_context(core);
	if (!ctx->mctx) {
		TRACE_ERROR("Failed to create mtcp context.\n");
		free(ctx);
		return NULL;
	}
	g_mctx[core] = ctx->mctx;

	return ctx;
}
/*----------------------------------------------------------------------------*/
void 
DestroyContext(thread_context_t ctx) 
{
	g_stat[ctx->core] = NULL;
	mtcp_destroy_context(ctx->mctx);
	free(ctx);
}
/*----------------------------------------------------------------------------*/
static inline int 
CreateConnection(thread_context_t ctx)
{
	mctx_t mctx = ctx->mctx;
	struct sockaddr_in addr;
	struct mtcp_epoll_event ev;
	int sockid;
	int ret;

	sockid = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
	if (sockid < 0) {
		TRACE_INFO("Failed to create socket!\n");
		return -1;
	}
	ret = mtcp_setsock_nonblock(mctx, sockid);
	if (ret < 0) {
		TRACE_ERROR("Failed to set socket in nonblocking mode.\n");
		exit(-1);
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = daddr;
	addr.sin_port = dport;
	
	ret = mtcp_connect(mctx, sockid, 
			(struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		if (errno != EINPROGRESS) {
			perror("mtcp_connect");
			mtcp_close(mctx, sockid);
			return -1;
		}
	}

	ctx->started++;
	ctx->pending++;

	ev.events = MTCP_EPOLLOUT;
	ev.data.sockid = sockid;
	mtcp_epoll_ctl(mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, sockid, &ev);

	printf("create connection on socket %d\n", sockid);

	return sockid;
}
/*----------------------------------------------------------------------------*/
static inline void 
CloseConnection(thread_context_t ctx, int sockid)
{
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_DEL, sockid, NULL);
	mtcp_close(ctx->mctx, sockid);
	assert(ctx->pending >= 0);
}
/*----------------------------------------------------------------------------*/
static inline int 
SendHTTPRequest(thread_context_t ctx, int sockid)
{
	char request[HTTP_HEADER_LEN];
	struct mtcp_epoll_event ev;
	int wr;
	int len;

	snprintf(request, HTTP_HEADER_LEN, "core %d: Hello world!", ctx->core);
	len = strlen(request);

	wr = mtcp_write(ctx->mctx, sockid, request, len);
	if (wr < len) {
		TRACE_ERROR("Socket %d: Sending HTTP request failed. "
				"try: %d, sent: %d\n", sockid, len, wr);
	}
	TRACE_APP("Socket %d HTTP Request of %d bytes. sent.\n", sockid, wr);
	printf("Socket %d HTTP Request of %d bytes. sent.\n", sockid, wr);

	ev.events = MTCP_EPOLLIN;
	ev.data.sockid = sockid;
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);

	return 0;
}
/*----------------------------------------------------------------------------*/
static inline int
HandleReadEvent(thread_context_t ctx, int sockid)
{
	mctx_t mctx = ctx->mctx;
	char buf[BUF_SIZE];
	int rd;

	rd = 1;
	while (rd > 0) {
		rd = mtcp_read(mctx, sockid, buf, BUF_SIZE);
		if (rd <= 0)
			break;

		TRACE_APP("Socket %d: mtcp_read ret: %d, total_recv: %lu, "
				"header_set: %d, header_len: %u, file_len: %lu\n", 
				sockid, rd, wv->recv + rd, 
				wv->headerset, wv->header_len, wv->file_len);

		printf("Core %d has received message [%s]\n", ctx->core, buf);
	}

	if (rd == 0) {
		/* connection closed by remote host */
		TRACE_DBG("Socket %d connection closed with server.\n", sockid);
		CloseConnection(ctx, sockid);
	} else if (rd < 0) {
		if (errno != EAGAIN) {
			TRACE_DBG("Socket %d: mtcp_read() error %s\n", 
					sockid, strerror(errno));
			ctx->errors++;
			CloseConnection(ctx, sockid);
		}
	}

	return 0;
}
/*----------------------------------------------------------------------------*/
void *
RunWgetMain(void *arg)
{
    thread_context_t ctx;
    mctx_t mctx;
    int core = *(int *)arg;
    struct in_addr daddr_in;
    int maxevents;
    int ep;
    struct mtcp_epoll_event *events;
    int nevents;
    int i;

    mtcp_core_affinitize(core);

    ctx = CreateContext(core);
    if (!ctx) {
        return NULL;
    }
    mctx = ctx->mctx;
    g_ctx[core] = ctx;
    srand(time(NULL));

    mtcp_init_rss(mctx, saddr, IP_RANGE, daddr, dport);

    ctx->target = 1;

    daddr_in.s_addr = daddr;
    fprintf(stderr, "Thread %d handles %d flows. connecting to %s:%u\n",
            core, 1, inet_ntoa(daddr_in), ntohs(dport));

    /* Initialization */
    maxevents = MAX_EVENTS * 3;
    ep = mtcp_epoll_create(mctx, maxevents);
    if (ep < 0) {
        TRACE_ERROR("Failed to create epoll struct!n");
        exit(EXIT_FAILURE);
    }

    events = (struct mtcp_epoll_event *)
            calloc(maxevents, sizeof(struct mtcp_epoll_event));
    if (!events) {
        TRACE_ERROR("Failed to allocate events!\n");
        exit(EXIT_FAILURE);
    }
    ctx->ep = ep;

    ctx->started = ctx->done = ctx->pending = 0;
    ctx->errors = ctx->incompletes = 0;

    if (CreateConnection(ctx) < 0) {
        printf("Core %d error while creating connection.\n", ctx->core);
        return NULL;
    }

    // wait for reply
    while (1) {
        nevents = mtcp_epoll_wait(mctx, ep, events, maxevents, -1);

        if (nevents < 0) {
            if (errno != EINTR) {
                TRACE_ERROR("mtcp_epoll_wait failed! ret: %d\n", nevents);
            }
            return NULL;
        }

        for (i = 0; i < nevents; i++) {

            if (events[i].events & MTCP_EPOLLERR) {
                int err;
                socklen_t len = sizeof(err);

                TRACE_APP("[CPU %d] Error on socket %d\n",
                          core, events[i].data.sockid);
                ctx->errors++;
                if (mtcp_getsockopt(mctx, events[i].data.sockid,
                                    SOL_SOCKET, SO_ERROR, (void *) &err, &len) == 0) {
                }
                CloseConnection(ctx, events[i].data.sockid);

            } else if (events[i].events & MTCP_EPOLLIN) {
                HandleReadEvent(ctx, events[i].data.sockid);

            } else if (events[i].events == MTCP_EPOLLOUT) {
                SendHTTPRequest(ctx, events[i].data.sockid);

            } else {
                TRACE_ERROR("Socket %d: event: %s\n",
                            events[i].data.sockid, EventToString(events[i].events));
                assert(0);
            }
        }

        if (ctx->done >= 1) {
            fprintf(stdout, "[CPU %d] Completed %d connections, "
                            "errors: %d incompletes: %d\n",
                    ctx->core, ctx->done, ctx->errors, ctx->incompletes);
            break;
        }
    }

    TRACE_INFO("Wget thread %d waiting for mtcp to be destroyed.\n", core);
    DestroyContext(ctx);

    TRACE_DBG("Wget thread %d finished.\n", core);
    pthread_exit(NULL);
    return NULL;
}
/*----------------------------------------------------------------------------*/
int 
main(int argc, char **argv)
{
	struct mtcp_conf mcfg;
	char *conf_file;
	int cores[MAX_CPUS];
	int ret;
	int i, o;
	int process_cpu;

	if (argc < 2) {
		TRACE_CONFIG("Too few arguments!\n");
		TRACE_CONFIG("Usage: %s ip\n", argv[0]);
		return FALSE;
	}

	if (strlen(argv[1]) > MAX_IP_STR_LEN) {
		TRACE_CONFIG("Length of IP should be smaller than %d!\n", MAX_IP_STR_LEN);
		return FALSE;
	}

    strncpy(host, argv[1], MAX_IP_STR_LEN);

	conf_file = NULL;
	process_cpu = -1;
	daddr = inet_addr(host);
	dport = htons(80);
	saddr = INADDR_ANY;

	num_cores = GetNumCPUs();
	core_limit = num_cores;
	while (-1 != (o = getopt(argc, argv, "N:n:f:"))) {
		switch(o) {
		case 'N':
			core_limit = mystrtol(optarg, 10);
			if (core_limit > num_cores) {
				TRACE_CONFIG("CPU limit should be smaller than the "
					     "number of CPUS: %d\n", num_cores);
				return FALSE;
			} else if (core_limit < 1) {
				TRACE_CONFIG("CPU limit should be greater than 0\n");
				return FALSE;
			}
			/** 
			 * it is important that core limit is set 
			 * before mtcp_init() is called. You can
			 * not set core_limit after mtcp_init()
			 */
			mtcp_getconf(&mcfg);
			mcfg.num_cores = core_limit;
			mtcp_setconf(&mcfg);
			break;
		case 'n':
			process_cpu = mystrtol(optarg, 10);
			if (process_cpu > core_limit) {
				TRACE_CONFIG("Starting CPU is way off limits!\n");
				return FALSE;
			}
			break;
		case 'f':
			conf_file = optarg;
			break;
		}
	}

	TRACE_CONFIG("Application configuration:\n");
	TRACE_CONFIG("# of cores: %d\n", core_limit);

	if (conf_file == NULL) {
		TRACE_ERROR("mTCP configuration file is not set!\n");
		exit(EXIT_FAILURE);
	}
	
	ret = mtcp_init(conf_file);
	if (ret) {
		TRACE_ERROR("Failed to initialize mtcp.\n");
		exit(EXIT_FAILURE);
	}
    mtcp_getconf(&mcfg);
    mcfg.max_concurrency = MAX_EVENTS;
    mcfg.max_num_buffers = MAX_EVENTS;
    mtcp_setconf(&mcfg);

	for (i = ((process_cpu == -1) ? 0 : process_cpu); i < core_limit; i++) {
		cores[i] = i;

		if (pthread_create(&app_thread[i], 
					NULL, RunWgetMain, (void *)&cores[i])) {
			perror("pthread_create");
			TRACE_ERROR("Failed to create wget thread.\n");
			exit(-1);
		}

		if (process_cpu != -1)
			break;
	}

	for (i = ((process_cpu == -1) ? 0 : process_cpu); i < core_limit; i++) {
		pthread_join(app_thread[i], NULL);
		TRACE_INFO("Wget thread %d joined.\n", i);

		if (process_cpu != -1)
			break;
	}

	mtcp_destroy();
	return 0;
}
/*----------------------------------------------------------------------------*/
