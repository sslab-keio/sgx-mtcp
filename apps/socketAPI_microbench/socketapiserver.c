#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
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

#define BASE_PORT 6000
#define MAX_CLIENTS 1000
#define BACKLOG 10

static pthread_t app_thread[MAX_CPUS];
static int done[MAX_CPUS];

static int num_cores;
static int send_packet_size = 0;
static int receive_packet_size = 0;
static int request_per_connection = 1;
static int throughput_limit = -1; // MB

int accept_connection(int sock) {
    // accept the socket
    struct sockaddr_in csin;
    int sinsize = sizeof(csin);
    int current_client_socket_fd = accept(sock, (struct sockaddr*) &csin, (socklen_t*) &sinsize);
    if (current_client_socket_fd == -1)
    {
        perror("An invalid socket has been accepted: ");
        return -1;
    }

    //TCP NO DELAY
    int flag = 1;
    int result = setsockopt(current_client_socket_fd, IPPROTO_TCP,
                            TCP_NODELAY, (char *) &flag, sizeof(int));
    if (result == -1)
    {
        perror("Error while setting TCP NO DELAY on client socket! ");
    }

    /*
    int client_port = ntohs(csin.sin_port);
    char *hostname = inet_ntoa(csin.sin_addr);

    fprintf(stderr,
            "Received a new connection from a client: %s:%i (socket %d).\n",
            hostname, client_port, current_client_socket_fd);
    */

    return current_client_socket_fd;
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
    int core = *(int *)arg;
    struct sockaddr_in addr;
    int listen_socket;
    int i;

    int client_socket[MAX_CLIENTS];
    int active_client[MAX_CLIENTS];
    int client_nreq[MAX_CLIENTS];
    int n_clients = 0;

    char* sndbuf = (char*)malloc(sizeof(*sndbuf)*send_packet_size);
    char* rcvbuf = (char*)malloc(sizeof(*rcvbuf)*receive_packet_size);
    if (!sndbuf || !rcvbuf) {
        printf("Cannot allocate memory for req/rep for core %d\n", core);
        exit(1);
    }

    // listening on port BASE_PORT + core
    listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_socket < 0) {
        perror("Cannot create socket");
        exit(1);
    }

    int flag = 1;
    if (setsockopt(listen_socket, IPPROTO_TCP, TCP_NODELAY,
                   (char*) &flag, sizeof(int)) == -1)   {
        perror("[client_thread] Error while setting TCP NO DELAY! ");
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(BASE_PORT+core);

    int error = bind(listen_socket, (struct sockaddr*) &addr, sizeof(addr));
    if (error < 0) {
        perror("Unable to name socket");
        exit(1);
    }

    if (listen(listen_socket, BACKLOG) == -1)
    {
      perror("Error while calling listen! ");
      exit(1);
    }

    for (i=0; i<MAX_CLIENTS; i++) {
        active_client[i] = 0;
        client_nreq[i] = 0;
    }

    printf("Thread %d is ready for network operations on socket %d\n", core, BASE_PORT+core);

    while (!done[core]) {

        // TODO: Limit throughput
        // TODO: Specify total time of evaluation

        fd_set file_descriptors;
        struct timeval listen_time;
        int sock_max;

        FD_ZERO(&file_descriptors); //initialize file descriptor set
        FD_SET(listen_socket, &file_descriptors);
        sock_max = listen_socket;
        for (i=0; i<MAX_CLIENTS; i++) {
            if (active_client[i]) {
                FD_SET(client_socket[i], &file_descriptors);
                sock_max = (client_socket[i] > sock_max ? client_socket[i] : sock_max);
            }
        }

        listen_time.tv_sec = 1;
        listen_time.tv_usec = 500;
        select(sock_max + 1, &file_descriptors, NULL, NULL, &listen_time);

        if (FD_ISSET(listen_socket, &file_descriptors)) {
            int s = accept_connection(listen_socket);
            if (s != -1) {
                for (i=0; i<MAX_CLIENTS; i++) {
                    if (!active_client[i]) {
                        client_socket[i] = s;
                        client_nreq[i] = 0;
                        active_client[i] = 1;
                        break;
                    }
                }
                n_clients++;
                if (n_clients == MAX_CLIENTS) {
                    printf("Thread %d, too many clients: %d <> %d\n", core, n_clients, MAX_CLIENTS);
                }
            }
        }

        for (i = 0; i < MAX_CLIENTS; i++) {
            if (active_client[i] && FD_ISSET(client_socket[i], &file_descriptors)) {
                recv_msg(client_socket[i], rcvbuf, receive_packet_size);
                send_msg(client_socket[i], sndbuf, send_packet_size);

                if (++client_nreq[i] == request_per_connection) {
                    close(client_socket[i]);
                    active_client[i] = 0;
                    n_clients--;
                }
            }
        }
    }

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
    int cores[MAX_CPUS];
    int i, o;

    if (argc < 5) {
        printf("Too few arguments. Usage: %s -n <umcores> -s <send_pkt_size> -r <recv_pkt_size> -R <req_per_conn> -T <thr_limit>\n", argv[0]);
        return -1;
    }

    while (-1 != (o = getopt(argc, argv, "n:s:r:R:T:"))) {
        switch(o) {
            case 'n':
                num_cores = mystrtol(optarg, 10);
                if (num_cores < 1 || num_cores > MAX_CPUS) {
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
                    printf("Throughput limit must be greater than or equal to 1!\n");
                    return FALSE;
                }
                break;
        }
    }

    printf("Server configuration:\n");
    printf("\tNumber of cores: %d\n", num_cores);
    printf("\tSend packet size: %d bytes\n", send_packet_size);
    printf("\tReceive packet size: %d bytes\n", receive_packet_size);
    printf("\tRequests per connection: %d\n", request_per_connection);
    printf("\tThroughput limit: %d MB/s\n", throughput_limit);

    for (i = 0; i < num_cores; i++) {
        done[i] = FALSE;
        cores[i] = i;

        if (pthread_create(&app_thread[i], NULL, client_thread, (void *) &cores[i])) {
            perror("pthread_create");
            printf("Failed to create server thread.\n");
            exit(-1);
        }

        // associate this thread to CPU i
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(i, &cpuset);

        int s = pthread_setaffinity_np(app_thread[i], sizeof(cpu_set_t), &cpuset);
        if (s != 0) {
            fprintf(stderr, "Error while associating thread %d thread to core %d\n", i, i);
        }
    }

    for (i = 0; i < num_cores; i++) {
        pthread_join(app_thread[i], NULL);
        printf("Server thread %d joined.\n", i);
    }

    return 0;
}