#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <limits.h>

#include <mtcp_api.h>
#include <mtcp_epoll.h>

#include "cpu.h"
#include "http_parsing.h"
#include "netlib.h"
#include "debug.h"

#define MAX_FLOW_NUM  (10000)
#define HTTP_HEADER_LEN 1024

#define RCVBUF_SIZE (2*1024)
#define SNDBUF_SIZE (8*1024)

#define MAX_EVENTS (MAX_FLOW_NUM * 3)

#define HT_SUPPORT FALSE

#ifndef MAX_CPUS
#define MAX_CPUS		16
#endif
/*----------------------------------------------------------------------------*/
struct thread_context
{
	mctx_t mctx;
	int ep;
};
/*----------------------------------------------------------------------------*/
static int num_cores;
static int core_limit;
static pthread_t app_thread[MAX_CPUS];
static int done[MAX_CPUS];
static char *conf_file = NULL;
static int backlog = -1;
/*----------------------------------------------------------------------------*/
void 
CloseConnection(struct thread_context *ctx, int sockid)
{
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_DEL, sockid, NULL);
	mtcp_close(ctx->mctx, sockid);
}
/*----------------------------------------------------------------------------*/
static int 
HandleReadEvent(struct thread_context *ctx, int sockid)
{
	struct mtcp_epoll_event ev;
	char buf[HTTP_HEADER_LEN];
	char response[HTTP_HEADER_LEN];
	time_t t_now;
	char t_str[128];
	int rd;
	int len;
	int sent;

	rd = mtcp_read(ctx->mctx, sockid, buf, HTTP_HEADER_LEN);
	if (rd <= 0) {
		return rd;
	}
	buf[rd] = '\0';

	printf("%s: received message [%s]\n", __func__, buf);

	/* Response handling */
	time(&t_now);
	strftime(t_str, 128, "%a, %d %b %Y %X GMT", gmtime(&t_now));
	snprintf(response, HTTP_HEADER_LEN, "Date: %s, message: %s",
			t_str, buf);

	printf("%s: response is [%s]\n", __func__, response);

	len = strlen(response);
	TRACE_APP("Socket %d Response: \n%s", sockid, response);
	sent = mtcp_write(ctx->mctx, sockid, response, len);
	TRACE_APP("Socket %d Sent response: try: %d, sent: %d\n",
			sockid, len, sent);
	printf("Socket %d Sent response: try: %d, sent: %d\n", sockid, len, sent);
	assert(sent == len);

	ev.events = MTCP_EPOLLIN;
	ev.data.sockid = sockid;
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);

	return rd;
}
/*----------------------------------------------------------------------------*/
int 
AcceptConnection(struct thread_context *ctx, int listener)
{
	mctx_t mctx = ctx->mctx;
	struct mtcp_epoll_event ev;
	int c;

	c = mtcp_accept(mctx, listener, NULL, NULL);

	if (c >= 0) {
		if (c >= MAX_FLOW_NUM) {
			TRACE_ERROR("Invalid socket id %d.\n", c);
			return -1;
		}

		TRACE_APP("New connection %d accepted.\n", c);
		ev.events = MTCP_EPOLLIN;
		ev.data.sockid = c;
		mtcp_setsock_nonblock(ctx->mctx, c);
		mtcp_epoll_ctl(mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, c, &ev);
		TRACE_APP("Socket %d registered.\n", c);

	} else {
		if (errno != EAGAIN) {
			TRACE_ERROR("mtcp_accept() error %s\n", 
					strerror(errno));
		}
	}

	return c;
}
/*----------------------------------------------------------------------------*/
struct thread_context *
InitializeServerThread(int core)
{
	struct thread_context *ctx;

	/* affinitize application thread to a CPU core */
#if HT_SUPPORT
	mtcp_core_affinitize(core + (num_cores / 2));
#else
	mtcp_core_affinitize(core);
#endif /* HT_SUPPORT */

	ctx = (struct thread_context *)calloc(1, sizeof(struct thread_context));
	if (!ctx) {
		TRACE_ERROR("Failed to create thread context!\n");
		return NULL;
	}

	/* create mtcp context: this will spawn an mtcp thread */
	ctx->mctx = mtcp_create_context(core);
	if (!ctx->mctx) {
		TRACE_ERROR("Failed to create mtcp context!\n");
		free(ctx);
		return NULL;
	}

	/* create epoll descriptor */
	ctx->ep = mtcp_epoll_create(ctx->mctx, MAX_EVENTS);
	if (ctx->ep < 0) {
		mtcp_destroy_context(ctx->mctx);
		free(ctx);
		TRACE_ERROR("Failed to create epoll descriptor!\n");
		return NULL;
	}

	return ctx;
}
/*----------------------------------------------------------------------------*/
int 
CreateListeningSocket(struct thread_context *ctx)
{
	int listener;
	struct mtcp_epoll_event ev;
	struct sockaddr_in saddr;
	int ret;

	/* create socket and set it as nonblocking */
	listener = mtcp_socket(ctx->mctx, AF_INET, SOCK_STREAM, 0);
	if (listener < 0) {
		TRACE_ERROR("Failed to create listening socket!\n");
		return -1;
	}
	ret = mtcp_setsock_nonblock(ctx->mctx, listener);
	if (ret < 0) {
		TRACE_ERROR("Failed to set socket in nonblocking mode.\n");
		return -1;
	}

	/* bind to port 80 */
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(80);
	ret = mtcp_bind(ctx->mctx, listener, 
			(struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		TRACE_ERROR("Failed to bind to the listening socket!\n");
		return -1;
	}

	/* listen (backlog: can be configured) */
	ret = mtcp_listen(ctx->mctx, listener, backlog);
	if (ret < 0) {
		TRACE_ERROR("mtcp_listen() failed!\n");
		return -1;
	}
	
	/* wait for incoming accept events */
	ev.events = MTCP_EPOLLIN;
	ev.data.sockid = listener;
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, listener, &ev);

	return listener;
}
/*----------------------------------------------------------------------------*/
void *
RunServerThread(void *arg)
{
	int core = *(int *)arg;
	struct thread_context *ctx;
	mctx_t mctx;
	int listener;
	int ep;
	struct mtcp_epoll_event *events;
	int nevents;
	int i, ret;
	int do_accept;
	
	/* initialization */
	ctx = InitializeServerThread(core);
	if (!ctx) {
		TRACE_ERROR("Failed to initialize server thread.\n");
		return NULL;
	}
	mctx = ctx->mctx;
	ep = ctx->ep;

	events = (struct mtcp_epoll_event *)
			calloc(MAX_EVENTS, sizeof(struct mtcp_epoll_event));
	if (!events) {
		TRACE_ERROR("Failed to create event struct!\n");
		exit(-1);
	}

	listener = CreateListeningSocket(ctx);
	if (listener < 0) {
		TRACE_ERROR("Failed to create listening socket.\n");
		exit(-1);
	}

	while (!done[core]) {
		nevents = mtcp_epoll_wait(mctx, ep, events, MAX_EVENTS, -1);
		if (nevents < 0) {
			if (errno != EINTR)
				perror("mtcp_epoll_wait");
			break;
		}

		do_accept = FALSE;
		for (i = 0; i < nevents; i++) {

			if (events[i].data.sockid == listener) {
				/* if the event is for the listener, accept connection */
				do_accept = TRUE;

			} else if (events[i].events & MTCP_EPOLLERR) {
				int err;
				socklen_t len = sizeof(err);

				/* error on the connection */
				TRACE_APP("[CPU %d] Error on socket %d\n", 
						core, events[i].data.sockid);
				if (mtcp_getsockopt(mctx, events[i].data.sockid, 
						SOL_SOCKET, SO_ERROR, (void *)&err, &len) == 0) {
					if (err != ETIMEDOUT) {
						fprintf(stderr, "Error on socket %d: %s\n", 
								events[i].data.sockid, strerror(err));
					}
				} else {
					perror("mtcp_getsockopt");
				}
				CloseConnection(ctx, events[i].data.sockid);

			} else if (events[i].events & MTCP_EPOLLIN) {
				ret = HandleReadEvent(ctx, events[i].data.sockid);

				if (ret == 0) {
					/* connection closed by remote host */
					CloseConnection(ctx, events[i].data.sockid);
				} else if (ret < 0) {
					/* if not EAGAIN, it's an error */
					if (errno != EAGAIN) {
						CloseConnection(ctx, events[i].data.sockid);
					}
				}

			} else {
				assert(0);
			}
		}

		/* if do_accept flag is set, accept connections */
		if (do_accept) {
			while (1) {
				ret = AcceptConnection(ctx, listener);
				if (ret < 0)
					break;
			}
		}

	}

	/* destroy mtcp context: this will kill the mtcp thread */
	mtcp_destroy_context(mctx);
	pthread_exit(NULL);

	return NULL;
}
/*----------------------------------------------------------------------------*/
void
SignalHandler(int signum)
{
	int i;

	for (i = 0; i < core_limit; i++) {
		if (app_thread[i] == pthread_self()) {
			//TRACE_INFO("Server thread %d got SIGINT\n", i);
			done[i] = TRUE;
		} else {
			if (!done[i]) {
				pthread_kill(app_thread[i], signum);
			}
		}
	}
}
/*----------------------------------------------------------------------------*/
static void
printHelp(const char *prog_name)
{
	TRACE_CONFIG("%s-f <mtcp_conf_file> "
		     "-N num_cores [-c <per-process core_id>] [-h]\n",
		     prog_name);
	exit(EXIT_SUCCESS);
}
/*----------------------------------------------------------------------------*/
int 
main(int argc, char **argv)
{
	int ret;
	struct mtcp_conf mcfg;
	int cores[MAX_CPUS];
	int process_cpu;
	int i, o;

	num_cores = GetNumCPUs();
	core_limit = num_cores;
	process_cpu = -1;

	if (argc < 2) {
		TRACE_CONFIG("$%s\n", argv[0]);
		return FALSE;
	}

	while (-1 != (o = getopt(argc, argv, "N:f:c:b:h"))) {
		switch (o) {
		case 'N':
			core_limit = mystrtol(optarg, 10);
			if (core_limit > num_cores) {
				TRACE_CONFIG("CPU limit should be smaller than the "
					     "number of CPUs: %d\n", num_cores);
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
		case 'f':
			conf_file = optarg;
			break;
		case 'c':
			process_cpu = mystrtol(optarg, 10);
			if (process_cpu > core_limit) {
				TRACE_CONFIG("Starting CPU is way off limits!\n");
				return FALSE;
			}
			break;
		case 'b':
			backlog = mystrtol(optarg, 10);
			break;
		case 'h':
			printHelp(argv[0]);
			break;
		}
	}

	/* initialize mtcp */
	if (conf_file == NULL) {
		TRACE_CONFIG("You forgot to pass the mTCP startup config file!\n");
		exit(EXIT_FAILURE);
	}

	ret = mtcp_init(conf_file);
	if (ret) {
		TRACE_CONFIG("Failed to initialize mtcp\n");
		exit(EXIT_FAILURE);
	}

	mtcp_getconf(&mcfg);
	if (backlog > mcfg.max_concurrency) {
		TRACE_CONFIG("backlog can not be set larger than CONFIG.max_concurrency\n");
		return FALSE;
	}

	/* if backlog is not specified, set it to 4K */
	if (backlog == -1) {
		backlog = 4096;
	}
	
	/* register signal handler to mtcp */
	mtcp_register_signal(SIGINT, SignalHandler);

	TRACE_INFO("Application initialization finished.\n");

	for (i = ((process_cpu == -1) ? 0 : process_cpu); i < core_limit; i++) {
		cores[i] = i;
		done[i] = FALSE;
		
		if (pthread_create(&app_thread[i], 
				   NULL, RunServerThread, (void *)&cores[i])) {
			perror("pthread_create");
			TRACE_CONFIG("Failed to create server thread.\n");
				exit(EXIT_FAILURE);
		}
		if (process_cpu != -1)
			break;
	}
	
	for (i = ((process_cpu == -1) ? 0 : process_cpu); i < core_limit; i++) {
		pthread_join(app_thread[i], NULL);

		if (process_cpu != -1)
			break;
	}
	
	mtcp_destroy();
	return 0;
}
