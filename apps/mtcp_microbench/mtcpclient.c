#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <mtcp_api.h>
#include <mtcp_epoll.h>
#include <netinet/in.h>
#include <pthread.h>
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

#include "errno.h"

//#define MAX_BUFFER_SIZE 8192
#define MAX_BUFFER_SIZE 10240

#define MAX_IP_STR_LEN 16

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
struct global_statistics {
  double reads;          // Mbps
  double writes;         // Mbps
  uint64_t kops;         // kops
  double total_latency;  // nsec
  double max_latency;    // nsec
  pthread_spinlock_t lock;
};
struct global_state {
  pthread_t app_thread[MAX_CPUS];
  int done[MAX_CPUS];
  int connections[MAX_CPUS];
  pthread_barrier_t evaluation_barrier;
};
struct global_config {
  struct mtcp_conf mcfg;
  char *cfg_file_path;

  char host[MAX_IP_STR_LEN + 1];
  in_addr_t daddr;
  in_port_t dport;
  in_addr_t saddr;

  int total_cores;
  int total_concurrency;
  int concurrency_per_core;
  int max_fds_per_core;

  int send_packet_size;
  int recv_packet_size;
  int req_per_connection;

  struct global_state state;
};
struct global_statistics statistics = {0};
struct global_config config = {0};
/*----------------------------------------------------------------------------*/
struct socket_context {
  char buf[MAX_BUFFER_SIZE];
  int operation_count;
  int total_sent;
  int total_recv;
  struct timespec start_ts;
  struct timespec end_ts;
};
typedef struct socket_context *socket_context_t;
/*----------------------------------------------------------------------------*/
struct thread_statistics {
  uint64_t reads;   // Bytes
  uint64_t writes;  // Bytes
  uint64_t operations;
  double total_latency;  // nsec
  double max_latency;    // nsec
};
/*----------------------------------------------------------------------------*/
struct thread_context {
  int core;
  int concurrency;
  mctx_t mctx;
  int ep;
  struct mtcp_epoll_event *events;
  struct socket_context *sctxs;
  struct thread_statistics stat;

  int connections;
  int timedout;
  struct timespec start_ts;
  struct timespec end_ts;
};
typedef struct thread_context *thread_context_t;
/*----------------------------------------------------------------------------*/
void signal_handler(int signum);
void *client_thread(void *arg);
/*----------------------------------------------------------------------------*/
void print_global_config(struct global_config *cfg) {
  printf("Application Configuration:\n");
  printf("mTCP Configuration File Path: %s\n", cfg->cfg_file_path);
  printf("Host: %s, Port: %u\n", cfg->host, ntohs(cfg->dport));
  printf("Total Cores: %d\n", cfg->total_cores);
  printf("Total Concurrency: %d\n", cfg->total_concurrency);
  printf("Send Packet Size: %d\n", cfg->send_packet_size);
  printf("Receive Packet Size: %d\n", cfg->recv_packet_size);
  printf("Request Per Connection: %d\n", cfg->req_per_connection);
}
/*----------------------------------------------------------------------------*/
uint64_t get_elapsed_nsec(struct timespec *start_ts, struct timespec *end_ts) {
  uint64_t elapsed = 1000 * 1000 * 1000 * (end_ts->tv_sec - start_ts->tv_sec);
  elapsed += end_ts->tv_nsec - start_ts->tv_nsec;
  return elapsed;
}
/*----------------------------------------------------------------------------*/
static void print_statistics() {
  fprintf(stdout,
          "[ALL] Reads: %lf Mbps, Writes: %lf Mbps, OPS: %lu kops, Avg "
          "Latency: %lf usec, Max Latency = %lf usec\n",
          statistics.reads, statistics.writes, statistics.kops,
          statistics.total_latency / (1000 * config.total_cores),
          statistics.max_latency / 1000);
}
/*----------------------------------------------------------------------------*/
void print_per_thread_statistics(thread_context_t ctx) {
  uint64_t elapsed_nsec = get_elapsed_nsec(&ctx->start_ts, &ctx->end_ts);
  double reads = ctx->stat.reads * 1000 * 1000 * 1000 * 8 / 1024.0 / 1024.0 /
                 elapsed_nsec;  // Mbps
  double writes = ctx->stat.writes * 1000 * 1000 * 1000 * 8 / 1024.0 / 1024.0 /
                  elapsed_nsec;                                         // Mbps
  uint64_t kops = ctx->stat.operations * 1000 * 1000 / elapsed_nsec;    // kops
  double avg_latency = ctx->stat.total_latency / ctx->stat.operations;  // nsec
  double max_latency = ctx->stat.max_latency;                           // nsec

  fprintf(stdout,
          "[CPU %d] Reads: %lf Mbps, Writes: %lf Mbps, OPS: %lu kops, Avg "
          "Latency: %lf usec, Max Latency = %lf usec\n",
          ctx->core, reads, writes, kops, avg_latency / 1000,
          max_latency / 1000);
}
/*----------------------------------------------------------------------------*/
int main(int argc, char **argv) {
  int ret;

  if (argc < 3) {
    fprintf(stderr, "Too few arguments!\n");
    return FALSE;
  }

  if (strlen(argv[1]) > MAX_IP_STR_LEN) {
    fprintf(stderr, "Length of URL should be smaller than %d!\n",
            MAX_IP_STR_LEN);
    return FALSE;
  }

  memset(config.host, '\0', sizeof(config.host));
  strncpy(config.host, argv[1], MAX_IP_STR_LEN);
  config.daddr = inet_addr(config.host);
  config.dport = htons(80);
  config.saddr = INADDR_ANY;

  config.req_per_connection = 1;

  // Options
  int opt;
  while (-1 != (opt = getopt(argc, argv, "N:c:n:f:s:r:R:"))) {
    switch (opt) {
      case 'N':
        config.total_cores = strtol(optarg, NULL, 10);

        if (config.total_cores > MAX_CPUS) {
          fprintf(stderr, "Number of cores must be less than %d!\n", MAX_CPUS);
          return FALSE;
        }

        mtcp_getconf(&config.mcfg);
        config.mcfg.num_cores = config.total_cores;
        mtcp_setconf(&config.mcfg);
        break;
      case 'c':
        config.total_concurrency = strtol(optarg, NULL, 10);
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

  // Initialize global state
  config.concurrency_per_core = config.total_concurrency / config.total_cores;
  int cores[MAX_CPUS];
  for (int i = 0; i < config.total_cores; i++) {
    cores[i] = i;
  }

  // Initialize global statistics
  pthread_spin_init(&statistics.lock, PTHREAD_PROCESS_PRIVATE);
  pthread_barrier_init(&config.state.evaluation_barrier, NULL,
                       config.total_cores);

  print_global_config(&config);

  ret = mtcp_init(config.cfg_file_path);
  if (ret) {
    fprintf(stderr, "Failed to initialize mtcp.\n");
    exit(EXIT_FAILURE);
  }

  mtcp_getconf(&config.mcfg);
  /* set the max number of fds 3x larger than concurrency */
  config.mcfg.max_concurrency = config.concurrency_per_core * 3;
  config.mcfg.max_num_buffers = config.concurrency_per_core * 3;
  config.max_fds_per_core = config.concurrency_per_core * 3;
  mtcp_setconf(&config.mcfg);

  mtcp_register_signal(SIGINT, signal_handler);

  for (int i = 0; i < config.total_cores; i++) {
    if (pthread_create(&config.state.app_thread[i], NULL, client_thread,
                       (void *)&cores[i])) {
      fprintf(stderr, "Failed to create client thread.\n");
      exit(-1);
    }
  }

  for (int i = 0; i < config.total_cores; i++) {
    pthread_join(config.state.app_thread[i], NULL);
    printf("Thread %d joined.\n", i);
  }

  print_statistics();

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
int create_connection(thread_context_t ctx) {
  mctx_t mctx = ctx->mctx;
  struct mtcp_epoll_event ev;
  struct sockaddr_in addr;
  int sockid;
  int ret;

  sockid = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
  if (sockid < 0) {
    printf("Failed to create socket!\n");
    return -1;
  }

  ret = mtcp_setsock_nonblock(mctx, sockid);
  if (ret < 0) {
    printf("Failed to set socket in nonblocking mode.\n");
    exit(-1);
  }

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = config.daddr;
  addr.sin_port = config.dport;

  ret = mtcp_connect(mctx, sockid, (struct sockaddr *)&addr,
                     sizeof(struct sockaddr_in));
  if (ret < 0) {
    if (errno != EINPROGRESS) {
      mtcp_close(mctx, sockid);
      return -1;
    }
  }

  ctx->sctxs[sockid].operation_count = 0;
  ctx->sctxs[sockid].total_sent = 0;
  ctx->sctxs[sockid].total_recv = 0;

  ctx->connections++;

  ev.events = MTCP_EPOLLOUT;
  ev.data.sockid = sockid;
  mtcp_epoll_ctl(mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, sockid, &ev);

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
    printf("Failed to allocate memory for thread context.\n");
    return NULL;
  }

  ctx->core = core;

  mtcp_core_affinitize(core);

  ctx->mctx = mtcp_create_context(core);
  if (!ctx->mctx) {
    fprintf(stderr, "Failed to create mtcp context.\n");
    return NULL;
  }

  mtcp_init_rss(ctx->mctx, config.saddr, 1, config.daddr, config.dport);

  fprintf(stderr, "Thread %d handles %d concurrency. connecting to %s:%u\n",
          core, config.concurrency_per_core, config.host, ntohs(config.dport));

  int maxevents = config.max_fds_per_core;

  ctx->ep = mtcp_epoll_create(ctx->mctx, maxevents);
  if (ctx->ep < 0) {
    fprintf(stderr, "Failed to create epoll struct!n");
    exit(EXIT_FAILURE);
  }

  ctx->events = (struct mtcp_epoll_event *)calloc(
      maxevents, sizeof(struct mtcp_epoll_event));

  if (!ctx->events) {
    fprintf(stderr, "Failed to allocate events!\n");
    exit(EXIT_FAILURE);
  }

  ctx->sctxs =
      (struct socket_context *)calloc(maxevents, sizeof(struct socket_context));

  if (!ctx->sctxs) {
    fprintf(stderr, "Failed to allocate socket contexts!\n");
    exit(EXIT_FAILURE);
  }

  ctx->concurrency = config.concurrency_per_core;

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
int send_request(thread_context_t ctx, int sockid) {
  char buf[MAX_BUFFER_SIZE];
  struct mtcp_epoll_event ev;
  socket_context_t sctx = &ctx->sctxs[sockid];
  int ret;

  // Operation start
  if (sctx->total_sent == 0) {
    clock_gettime(CLOCK_MONOTONIC, &sctx->start_ts);
  }

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

  ev.events = MTCP_EPOLLIN;
  ev.data.sockid = sockid;
  mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);

  ctx->stat.writes += sctx->total_sent;

  // Reset total_sent for the next request
  sctx->total_sent = 0;

  return ret;
}
/*----------------------------------------------------------------------------*/
int recv_response(thread_context_t ctx, int sockid) {
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

  sctx->operation_count++;
  ctx->stat.reads += sctx->total_recv;

  // Operation end
  clock_gettime(CLOCK_MONOTONIC, &sctx->end_ts);
  uint64_t latency = get_elapsed_nsec(&sctx->start_ts, &sctx->end_ts);
  ctx->stat.total_latency += latency;
  ctx->stat.max_latency = MAX(latency, ctx->stat.max_latency);
  ctx->stat.operations++;

  if (config.req_per_connection > 0 && sctx->operation_count >= config.req_per_connection) {
    close_connection(ctx, sockid);
  } else {  // Set EPOLLOUT to send the next request
    ev.events = MTCP_EPOLLOUT;
    ev.data.sockid = sockid;
    mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);
  }

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

  pthread_barrier_wait(&config.state.evaluation_barrier);

  clock_gettime(CLOCK_MONOTONIC, &ctx->start_ts);
  while (!config.state.done[core]) {
    while (ctx->connections < ctx->concurrency) {
      if (create_connection(ctx) < 0) {
        config.state.done[core] = TRUE;
        break;
      }
    }

    nevents = mtcp_epoll_wait(mctx, ep, events, maxevents, -1);
    if (nevents < 0) {
      if (errno != EINTR) {
        printf("mtcp_epoll_wait failed! ret: %d\n", nevents);
      }
      config.state.done[core] = TRUE;
      break;
    }

    for (int i = 0; i < nevents; i++) {
      if (events[i].events & MTCP_EPOLLERR) {
        printf("MTCP_EPOLLERR\n");
        int err;
        socklen_t len = sizeof(err);

        if (mtcp_getsockopt(mctx, events[i].data.sockid, SOL_SOCKET, SO_ERROR,
                            (void *)&err, &len) == 0) {
          if (err == ETIMEDOUT) ctx->timedout++;
        }

        close_connection(ctx, events[i].data.sockid);
      } else if (events[i].events & MTCP_EPOLLIN) {
        int ret = recv_response(ctx, events[i].data.sockid);

        if (ret < 0) {
          if (errno != EAGAIN) {  // EAGAIN means data hasn't arrived yet
            fprintf(stderr, "recv_response failed.\n");
            exit(EXIT_FAILURE);
          }
        } else if (ret == 0) {
          fprintf(stderr, "Connection is closed by the server.\n");
          exit(EXIT_FAILURE);
        }
      } else if (events[i].events & MTCP_EPOLLOUT) {
        int ret = send_request(ctx, events[i].data.sockid);

        if (ret < 0) {
          if (errno !=
              EAGAIN) {  // EAGAIN means server side receive buffer is full
            fprintf(stderr, "send_request failed.\n");
            exit(EXIT_FAILURE);
          }
        }

      } else {
        fprintf(stderr, "Event error.\n");
        exit(EXIT_FAILURE);
      }
    }
  }
  clock_gettime(CLOCK_MONOTONIC, &ctx->end_ts);
  print_per_thread_statistics(ctx);

  pthread_spin_lock(&statistics.lock);
  uint64_t elapsed_nsec = get_elapsed_nsec(&ctx->start_ts, &ctx->end_ts);
  double reads = (double)ctx->stat.reads * 1000 * 8 / elapsed_nsec;  		// Mbps
  double writes = (double)ctx->stat.writes * 1000 * 8 / elapsed_nsec;           // Mbps
  uint64_t kops = ctx->stat.operations * 1000 * 1000 / elapsed_nsec;    // kops
  double avg_latency = (double)ctx->stat.total_latency / ctx->stat.operations;  // nsec
  double max_latency = ctx->stat.max_latency;                           // nsec

  //printf("[%s] benchmark duration is %lu ns\n", __func__, elapsed_nsec);
  //printf("[%s] writes is %lu bytes\n", __func__, ctx->stat.writes);
  fprintf(stdout,
          "[CPU %d] Reads: %lf Mbps, Writes: %lf Mbps, OPS: %lu kops, Avg "
          "Latency: %lf usec, Max Latency = %lf usec\n",
          ctx->core, reads, writes, kops, avg_latency / 1000,
          max_latency / 1000);

  pthread_spin_lock(&statistics.lock);
  {
	  statistics.reads += reads;
	  statistics.writes += writes;
	  statistics.kops += kops;
	  statistics.total_latency += ctx->stat.total_latency / ctx->stat.operations;
	  statistics.max_latency = MAX(statistics.max_latency, ctx->stat.max_latency);
  }
  pthread_spin_unlock(&statistics.lock);
}
/*----------------------------------------------------------------------------*/
void *client_thread(void *arg) {
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
  pthread_exit(NULL);

  return NULL;
}
