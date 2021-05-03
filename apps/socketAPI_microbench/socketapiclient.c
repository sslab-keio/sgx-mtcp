#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sched.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <sys/select.h>
#include <assert.h>

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef MAX_CPUS
#define MAX_CPUS    16
#endif

#define MAX_CLIENTS 1000

#define BASE_PORT 6000
#define BACKLOG 1000

struct thread_stat {
    int core;
    int done;
    float reads; // Mbps
    float writes; // Mbps
    float thr; // ops/sec
    uint64_t ops; // n operations
    float avg_latency; // usec
    float max_latency; // usec
    float sum_latency; // usec
};

static pthread_t app_thread[MAX_CLIENTS];
static struct thread_stat stats[MAX_CLIENTS];

static int num_clients;
static int server_core = 0;
static int send_packet_size = 0;
static int receive_packet_size = 0;
static int request_per_connection = 1;
static int throughput_limit = -1; // MB
static int duration = 10; // sec
static char server_ip[16];

static float get_elapsed_usec(struct timeval start_tv, struct timeval end_tv)
{
  time_t sec = (time_t)(end_tv.tv_sec - start_tv.tv_sec);
  long int usec = (long int)(end_tv.tv_usec - start_tv.tv_usec);
  float elapsed_usec = sec * 1000000 + usec;

  return elapsed_usec;
}

int recv_msg(int s, void *buf, size_t len)
{
    size_t len_tmp = 0;
    int n;

    do {
        n = recv(s, &(((char *) buf)[len_tmp]), len - len_tmp, 0);
        if (n == -1) {
            perror("tcp_net:recv():");
            exit(-1);
        }

        len_tmp = len_tmp + n;
    } while (len_tmp < len);

    return len_tmp;
}

void send_msg(int s, void *msg, size_t size)
{
    size_t total = 0; // how many bytes we've sent
    size_t bytesleft = size; // how many we have left to send
    int n = -1;

    while (total < size) {
        n = send(s, (char*) msg + total, bytesleft, 0);

        if (n == -1) {
            perror("tcp_net:send():");
            exit(-1);
        }

        total += n;
        bytesleft -= n;
    }
}

void* client_thread(void *arg) {
    struct thread_stat* stats = (struct thread_stat*)arg;
    int core = stats->core;
    struct sockaddr_in addr;
    struct timeval start_tv;
    struct timeval end_tv;
    struct timeval lat_start_tv;
    struct timeval lat_end_tv;
    int i;

    char* sndbuf = (char*)malloc(sizeof(*sndbuf)*send_packet_size);
    char* rcvbuf = (char*)malloc(sizeof(*rcvbuf)*receive_packet_size);
    if (!sndbuf || !rcvbuf) {
        printf("Cannot allocate memory for req/rep for core %d\n", core);
        exit(1);
    }

    stats->reads = 0;
    stats->writes = 0;
    stats->ops = 0;
    stats->avg_latency = 0;
    stats->max_latency = 0;
    stats->sum_latency = 0;

    gettimeofday(&start_tv, NULL);

    while (!stats->done) {

        // TODO: Limit throughput

        // listening on port BASE_PORT + core
        int sockid = socket(AF_INET, SOCK_STREAM, 0);
        if (sockid < 0) {
            perror("Cannot create socket");
            exit(1);
        }

        int flag = 1;
        if (setsockopt(sockid, IPPROTO_TCP, TCP_NODELAY,
                       (char*) &flag, sizeof(int)) == -1)   {
            perror("[client_thread] Error while setting TCP NO DELAY! ");
        }

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(server_ip);
        addr.sin_port = htons(BASE_PORT+core%server_core);

        //printf("Client %d connects to port %d in progress...\n", core, BASE_PORT+core%server_core);
        while (1) {
            if (connect(sockid, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                break;
            }
        }

        for (i=0; i<request_per_connection; i++) {
            gettimeofday(&lat_start_tv, NULL);
            send_msg(sockid, sndbuf, send_packet_size);
            recv_msg(sockid, rcvbuf, receive_packet_size);
            gettimeofday(&lat_end_tv, NULL);

            float latency = get_elapsed_usec(lat_start_tv, lat_end_tv);
            stats->sum_latency += latency;
            stats->max_latency = (latency > stats->max_latency ? latency : stats->max_latency);

            stats->reads += send_packet_size;
            stats->writes += receive_packet_size;
            stats->ops++;
        }

        close(sockid);
    }

    gettimeofday(&end_tv, NULL);
    float elapsed = get_elapsed_usec(start_tv, end_tv);

    //printf("Client %d %ld ops %.2f usec\n", core, stats->ops, elapsed);

    stats->avg_latency = stats->sum_latency / stats->ops;
    stats->reads = stats->reads * 1000000 * 8 / 1024.0 / 1024.0 / elapsed;
    stats->writes = stats->writes * 1000000 * 8 / 1024.0 / 1024.0 / elapsed;
    stats->thr = stats->ops * 1000000 / elapsed; // ops / sec

    /*
    printf("Client %d stats:\n", core);
    printf("\tread thr = %.2f Mbps\n", stats->reads);
    printf("\twrite thr = %.2f Mbps\n", stats->writes);
    printf("\tthr = %.2f ops/sec\n", stats->thr);
    printf("\tavg latency = %.2f usec\n", stats->avg_latency);
    printf("\tmax latency = %.2f usec\n", stats->max_latency);
    */

    return NULL;
}

static inline int mystrtol(const char *nptr, int base)
{
    int rval;
    char *endptr;

    errno = 0;
    rval = strtol(nptr, &endptr, 10);
    /* check for strtol errors */
    if ((errno == ERANGE && (rval == LONG_MAX ||
                             rval == LONG_MIN))
        || (errno != 0 && rval == 0)) {
        perror("strtol");
        exit(EXIT_FAILURE);
    }
    if (endptr == nptr) {
        printf("Parsing strtol error!\n");
        exit(EXIT_FAILURE);
    }

    return rval;
}

int main(int argc, char** argv) {
    int i, o;

    if (argc < 5) {
        printf("Too few arguments. Usage: %s -n <num_clients> -i <server_ip> -c <server_cores> -s <send_pkt_size> -r <recv_pkt_size> -R <req_per_conn> -T <thr_limit> -d <exp_duration>\n", argv[0]);
        return -1;
    }

    while (-1 != (o = getopt(argc, argv, "n:c:s:r:R:T:d:i:"))) {
        switch(o) {
            case 'n':
                num_clients = mystrtol(optarg, 10);
                if (num_clients < 1 || num_clients > MAX_CLIENTS) {
                    printf("Num cores must be greater than 0 or less than %d!\n", MAX_CLIENTS);
                    return FALSE;
                }
                break;
            case 'c':
                server_core = mystrtol(optarg, 10);
                if (server_core < 1 || server_core > MAX_CPUS) {
                    printf("Num cores must be greater than 0 or less than %d!\n", MAX_CPUS);
                    return FALSE;
                }
                break;
            case 's': // Send packet size
                send_packet_size = mystrtol(optarg, 10);
                if (send_packet_size < 0) {
                    printf("Packet size must be greater than or equal to 0!\n");
                    return FALSE;
                }
                break;
            case 'r': // Receive packet size
                receive_packet_size = mystrtol(optarg, 10);
                if (receive_packet_size < 0) {
                    printf("Receive packet size must be greater than or equal to 0!\n");
                    return FALSE;
                }
                break;
            case 'R': // Request per connection
                request_per_connection = mystrtol(optarg, 10);
                if (request_per_connection < 1) {
                    printf("Request per connection must be greater than or equal to 1!\n");
                    return FALSE;
                }
                break;
            case 'T': // Throughput limit
                throughput_limit = mystrtol(optarg, 10); // MB
                if (throughput_limit < 0) {
                    printf("Thtoughput limit must be greater than or equal to 1!\n");
                    return FALSE;
                }
                break;
            case 'd': // experiment duration
                duration = mystrtol(optarg, 10); // sec
                if (duration < 0) {
                    printf("Duration must be greater than 0!\n");
                    return FALSE;
                }
                break;
            case 'i': // server ip
                memcpy(server_ip, optarg, 16);
                server_ip[15] = '\0';
                break;
        }
    }

    printf("Client configuration:\n");
    printf("\tServer ip: %s\n", server_ip);
    printf("\tNumber of clients: %d\n", num_clients);
    printf("\tNumber of cores at the server: %d\n", server_core);
    printf("\tSend packet size: %d bytes\n", send_packet_size);
    printf("\tReceive packet size: %d bytes\n", receive_packet_size);
    printf("\tRequests per connection: %d\n", request_per_connection);
    printf("\tThroughput limit: %d MB/s\n", throughput_limit);
    printf("\tExperiment duration: %d sec\n", duration);

    for (i = 0; i < num_clients; i++) {
        stats[i].done = FALSE;
        stats[i].core = i;

        if (pthread_create(&app_thread[i], NULL, client_thread, (void*)&stats[i])) {
            perror("pthread_create");
            printf("Failed to create server thread.\n");
            exit(-1);
        }
    }

    // wait for duration
    sleep(duration);
    for (i = 0; i < num_clients; i++) {
        stats[i].done = TRUE;
    }

    struct thread_stat aggregated;
    aggregated.reads = 0;
    aggregated.writes = 0;
    aggregated.ops = 0;
    aggregated.thr = 0;
    aggregated.avg_latency = 0;
    aggregated.max_latency = 0;
    aggregated.sum_latency = 0;

    for (i = 0; i < num_clients; i++) {
        pthread_join(app_thread[i], NULL);

        // aggregate statistics
        aggregated.reads += stats[i].reads;
        aggregated.writes += stats[i].writes;
        aggregated.ops += stats[i].ops;
        aggregated.thr += stats[i].thr;
        aggregated.avg_latency += stats[i].avg_latency;
        aggregated.max_latency = (aggregated.max_latency > stats[i].max_latency ? aggregated.max_latency : stats[i].max_latency);
        aggregated.sum_latency += stats[i].sum_latency;
    }

    // print stats
    aggregated.avg_latency /= num_clients;
    aggregated.max_latency = (aggregated.max_latency > stats[i].max_latency ? aggregated.max_latency : stats[i].max_latency);
    aggregated.sum_latency /= aggregated.ops;

    printf("Global stats:\n");
    printf("\tread thr = %.2f Mbps\n", aggregated.reads);
    printf("\twrite thr = %.2f Mbps\n", aggregated.writes);
    printf("\tthr = %.2f ops/sec\n", aggregated.thr);
    printf("\tavg latency = %.2f usec\n", aggregated.avg_latency);
    printf("\tmax latency = %.2f usec\n", aggregated.max_latency);
    //TODO

    return 0;
}