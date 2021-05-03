#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <mtcp_api.h>
#include <mtcp_epoll.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "entry.h"
#include "errno.h"
#include "thread_wrapper.h"

#ifdef COMPILE_WITH_INTEL_SGX
#include "enclaveshim_ocalls.h"
#else
#define my_printf(format, ...) printf(format, ##__VA_ARGS__)
#define my_fprintf(stream, format, ...) fprintf(stream, format, ##__VA_ARGS__)
#endif

#define MAX_BUFFER_SIZE 10240

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

#ifndef MAX_CPUS
#define MAX_CPUS 16
#endif
/*----------------------------------------------------------------------------*/
struct global_state {
  pthread_t *app_threads;
  int done[MAX_CPUS];
  int connections[MAX_CPUS];
};
struct global_config {
  struct mtcp_conf mcfg;
  char *cfg_file_path;

  int total_cores;
  int max_fds_per_core;
  int backlog;

  int send_packet_size;
  int recv_packet_size;
  int req_per_connection;

  struct global_state state;
};
struct global_config config = {0};
/*----------------------------------------------------------------------------*/
struct socket_context {
  char buf[MAX_BUFFER_SIZE];
  int operation_count;
  int total_sent;
  int total_recv;
  struct timeval start_tv;
  struct timeval end_tv;
};
typedef struct socket_context *socket_context_t;
/*----------------------------------------------------------------------------*/
struct thread_context {
  int core;
  mctx_t mctx;
  int ep;
  struct mtcp_epoll_event *events;
  struct socket_context *sctxs;
  int listener;

  int connections;
  int timedout;
};
typedef struct thread_context *thread_context_t;
/*----------------------------------------------------------------------------*/
void signal_handler(int signum);
void *server_thread(void *arg);
/*----------------------------------------------------------------------------*/
void print_global_config(struct global_config *cfg) {
  my_printf("Application Configuration:\n");
  my_printf("mTCP Configuration File Path: %s\n", cfg->cfg_file_path);
  my_printf("Total Cores: %d\n", cfg->total_cores);
  my_printf("Send Packet Size: %d\n", cfg->send_packet_size);
  my_printf("Receive Packet Size: %d\n", cfg->recv_packet_size);
  my_printf("Request Per Connection: %d\n", cfg->req_per_connection);
  my_printf("Max Concurrency Per Core: %d\n", cfg->mcfg.max_concurrency);
}
/*----------------------------------------------------------------------------*/
#ifdef COMPILE_WITH_INTEL_SGX
int ecall_main_wrapper(int argc, char **argv) {
  int ret = main_wrapper(argc, argv);
  return ret;
}
#endif
/*----------------------------------------------------------------------------*/
int main_wrapper(int argc, char **argv) {
  int ret;

  // Options
  config.req_per_connection = 1;
  config.backlog = 4096;
  int opt;
  while (-1 != (opt = getopt(argc, argv, "N:f:s:r:R:"))) {
    switch (opt) {
      case 'N':
        config.total_cores = strtol(optarg, NULL, 10);

        if (config.total_cores > MAX_CPUS) {
          my_fprintf(stderr, "Number of cores must be less than %d!\n",
                     MAX_CPUS);
          return FALSE;
        }

        mtcp_getconf(&config.mcfg);
        config.mcfg.num_cores = config.total_cores;
        mtcp_setconf(&config.mcfg);
        break;
      case 'f':
        config.cfg_file_path = optarg;
        break;
      case 's':
        config.send_packet_size = strtol(optarg, NULL, 10);
        break;
      case 'r':
        config.recv_packet_size = strtol(optarg, NULL, 10);
        break;
      case 'R':
        config.req_per_connection = strtol(optarg, NULL, 10);
        break;
    }
  }
  config.max_fds_per_core = config.mcfg.max_concurrency;

  // Initialize global state
  int cores[MAX_CPUS];
  for (int i = 0; i < config.total_cores; i++) {
    cores[i] = i;
  }
#ifdef COMPILE_WITH_INTEL_SGX
  config.state.app_threads =
      (thread_t *)untrusted_calloc(MAX_CPUS, sizeof(thread_t));
#else
  config.state.app_threads = (thread_t *)calloc(MAX_CPUS, sizeof(thread_t));
#endif

  print_global_config(&config);

  ret = mtcp_init(config.cfg_file_path);
  if (ret) {
    my_fprintf(stderr, "Failed to initialize mtcp.\n");
    exit(EXIT_FAILURE);
  }

  mtcp_register_signal(SIGINT, signal_handler);

  for (int i = 0; i < config.total_cores; i++) {
    if (thread_create(&config.state.app_threads[i], NULL, server_thread,
                      (void *)&cores[i])) {
      my_fprintf(stderr, "Failed to create server thread.\n");
      exit(-1);
    }
  }

  for (int i = 0; i < config.total_cores; i++) {
    thread_join(config.state.app_threads[i], NULL);
    my_printf("Thread %d joined.\n", i);
  }

  mtcp_destroy();

  return 0;
}
/*----------------------------------------------------------------------------*/
void signal_handler(int signum) {
  for (int i = 0; i < config.total_cores; i++) {
    config.state.done[i] = TRUE;
  }
}
/*----------------------------------------------------------------------------*/
int accept_connection(thread_context_t ctx) {
  mctx_t mctx = ctx->mctx;
  struct mtcp_epoll_event ev;
  int sockid;

  sockid = mtcp_accept(mctx, ctx->listener, NULL, NULL);

  if (sockid >= 0) {
    mtcp_setsock_nonblock(ctx->mctx, sockid);
    ev.events = MTCP_EPOLLIN;
    ev.data.sockid = sockid;
    mtcp_epoll_ctl(mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, sockid, &ev);

    ctx->sctxs[sockid].operation_count = 0;
    ctx->sctxs[sockid].total_sent = 0;
    ctx->sctxs[sockid].total_recv = 0;

    ctx->connections++;
  } else {
    if (errno != EAGAIN) {
      my_fprintf(stderr, "mtcp_accept() failed!\n");
      exit(EXIT_FAILURE);
    }
  }

  return sockid;
}
/*----------------------------------------------------------------------------*/
void close_connection(thread_context_t ctx, int sockid) {
  mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_DEL, sockid, NULL);
  mtcp_close(ctx->mctx, sockid);
  ctx->connections--;
}
/*----------------------------------------------------------------------------*/
thread_context_t create_thread_context(int core) {
  thread_context_t ctx =
      (thread_context_t)calloc(1, sizeof(struct thread_context));

  if (!ctx) {
    my_printf("Failed to allocate memory for thread context.\n");
    return NULL;
  }

  ctx->core = core;

  mtcp_core_affinitize(core);

  ctx->mctx = mtcp_create_context(core);
  if (!ctx->mctx) {
    my_fprintf(stderr, "Failed to create mtcp context.\n");
    return NULL;
  }

  int maxevents = config.max_fds_per_core;

  ctx->ep = mtcp_epoll_create(ctx->mctx, maxevents);
  if (ctx->ep < 0) {
    my_fprintf(stderr, "Failed to create epoll struct!\n");
    exit(EXIT_FAILURE);
  }

  ctx->events = (struct mtcp_epoll_event *)calloc(
      maxevents, sizeof(struct mtcp_epoll_event));

  if (!ctx->events) {
    my_fprintf(stderr, "Failed to allocate events!\n");
    exit(EXIT_FAILURE);
  }

#ifdef COMPILE_WITH_INTEL_SGX
  ctx->sctxs =
      (struct socket_context *)untrusted_calloc(maxevents, sizeof(struct socket_context));
#else
  ctx->sctxs =
      (struct socket_context *)calloc(maxevents, sizeof(struct socket_context));
#endif

  if (!ctx->sctxs) {
    my_fprintf(stderr, "Failed to allocate socket contexts!\n");
    exit(EXIT_FAILURE);
  }

  return ctx;
}
/*----------------------------------------------------------------------------*/
void destroy_thread_context(thread_context_t ctx) {
  free(ctx->events);
  free(ctx->sctxs);
  mtcp_destroy_context(ctx->mctx);
  free(ctx);
}
/*----------------------------------------------------------------------------*/
int create_listening_socket(thread_context_t ctx) {
  struct mtcp_epoll_event ev;
  struct sockaddr_in saddr;
  int ret;

  ctx->listener = mtcp_socket(ctx->mctx, AF_INET, SOCK_STREAM, 0);
  if (ctx->listener < 0) {
    my_fprintf(stderr, "Failed to create listening socket!\n");
    return -1;
  }

  ret = mtcp_setsock_nonblock(ctx->mctx, ctx->listener);
  if (ret < 0) {
    my_fprintf(stderr, "Failed to set socket in nonblocking mode.\n");
    return -1;
  }

  /* bind to port 80 */
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = INADDR_ANY;
  saddr.sin_port = htons(80);
  ret = mtcp_bind(ctx->mctx, ctx->listener, (struct sockaddr *)&saddr,
                  sizeof(struct sockaddr_in));
  if (ret < 0) {
    my_fprintf(stderr, "Failed to bind to the listening socket!\n");
    return -1;
  }

  ret = mtcp_listen(ctx->mctx, ctx->listener, config.backlog);
  if (ret < 0) {
    my_fprintf(stderr, "mtcp_listen() failed!\n");
    return -1;
  }

  /* Wait for incoming accept events */
  ev.events = MTCP_EPOLLIN;
  ev.data.sockid = ctx->listener;
  mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, ctx->listener, &ev);

  return ctx->listener;
}
/*----------------------------------------------------------------------------*/
int send_response(thread_context_t ctx, int sockid) {
  char buf[MAX_BUFFER_SIZE];
  struct mtcp_epoll_event ev;
  socket_context_t sctx = &ctx->sctxs[sockid];
  int ret;

  do {
    ret = mtcp_write(ctx->mctx, sockid, buf + sctx->total_sent,
                     config.send_packet_size - sctx->total_sent);

    if (ret < 0) {
      return ret;
    }

    sctx->total_sent += ret;

    if (sctx->total_sent >= config.send_packet_size) break;
  } while (ret >= 0);

  assert(sctx->total_sent == config.send_packet_size);

  sctx->operation_count++;
  if (config.req_per_connection > 0 && sctx->operation_count >= config.req_per_connection) {
    close_connection(ctx, sockid);
  } else {
    ev.events = MTCP_EPOLLIN;
    ev.data.sockid = sockid;
    mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);
  }

  // Reset total_sent for the next request
  sctx->total_sent = 0;

  return ret;
}
/*----------------------------------------------------------------------------*/
int recv_request(thread_context_t ctx, int sockid) {
  struct mtcp_epoll_event ev;
  socket_context_t sctx = &ctx->sctxs[sockid];
  char *buf = sctx->buf;
  int ret;

  do {
    ret = mtcp_read(ctx->mctx, sockid, buf + sctx->total_recv,
                    config.recv_packet_size - sctx->total_recv);

    if (ret <= 0) {
      return ret;
    }

    sctx->total_recv += ret;

    if (sctx->total_recv >= config.recv_packet_size) break;
  } while (ret > 0);

  assert(sctx->total_recv == config.recv_packet_size);

  ev.events = MTCP_EPOLLOUT;
  ev.data.sockid = sockid;
  mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);

  // Reset total_recv for the next communication
  sctx->total_recv = 0;

  return ret;
}
/*----------------------------------------------------------------------------*/
void main_loop(thread_context_t ctx) {
  int core = ctx->core;
  int ep = ctx->ep;
  struct mtcp_epoll_event *events = ctx->events;
  int maxevents = config.max_fds_per_core;
  mctx_t mctx = ctx->mctx;
  int nevents;
  int do_accept;

#ifdef ENABLE_UCTX
  lthread_set_funcname("app");
#endif

  if (create_listening_socket(ctx) < 0) {
    my_fprintf(stderr, "create_listening_socket failed.\n");
    exit(EXIT_FAILURE);
  }

  while (!config.state.done[core]) {
    do_accept = FALSE;
    nevents = mtcp_epoll_wait(mctx, ep, events, maxevents, -1);
    if (nevents < 0) {
      if (errno != EINTR) {
        my_printf("mtcp_epoll_wait failed! ret: %d\n", nevents);
      }
      config.state.done[core] = TRUE;
      break;
    }

    for (int i = 0; i < nevents; i++) {
      if (events[i].data.sockid == ctx->listener) {
        do_accept = TRUE;
      } else if (events[i].events & MTCP_EPOLLERR) {
        int err;
        socklen_t len = sizeof(err);

        if (mtcp_getsockopt(mctx, events[i].data.sockid, SOL_SOCKET, SO_ERROR,
                            (void *)&err, &len) == 0) {
          if (err == ETIMEDOUT) ctx->timedout++;
        }

        close_connection(ctx, events[i].data.sockid);
      } else if (events[i].events & MTCP_EPOLLIN) {
        int ret = recv_request(ctx, events[i].data.sockid);

        if (ret < 0) {
          if (errno != EAGAIN) {  // EAGAIN means data hasn't arrived yet
            my_fprintf(stderr, "recv_request failed.\n");
            exit(EXIT_FAILURE);
          }
        } else if (ret == 0) {
          my_fprintf(stderr, "Connection is closed by the client.\n");
          close_connection(ctx, events[i].data.sockid);
        }
      } else if (events[i].events & MTCP_EPOLLOUT) {
        int ret = send_response(ctx, events[i].data.sockid);

        if (ret < 0) {
          if (errno !=
              EAGAIN) {  // EAGAIN means server side receive buffer is full
            my_fprintf(stderr, "send_response failed.\n");
            exit(EXIT_FAILURE);
          }
        }
      } else {
        my_fprintf(stderr, "Event error.\n");
        exit(EXIT_FAILURE);
      }
    }

    if (do_accept) {
      while (1) {
        int ret = accept_connection(ctx);
        if (ret < 0) break;
      }
    }
  }
}
/*----------------------------------------------------------------------------*/
void *server_thread(void *arg) {
  thread_context_t ctx;
  int core = *(int *)arg;

  ctx = create_thread_context(core);

#ifdef ENABLE_UCTX
  mtcp_create_app_context(ctx->mctx, (mtcp_app_func_t)main_loop, (void *)ctx);
  mtcp_run_app(ctx->mctx);
#else
  main_loop(ctx);
#endif

  destroy_thread_context(ctx);

  return NULL;
}
