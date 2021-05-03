#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
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

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#define USER_TYPES_H_
#include "enclave_t.h"

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

static int send_packet_size = 0;
static int receive_packet_size = 0;
static int request_per_connection = 1;
static int throughput_limit = -1; // MB

/* ---------- enclave stuff ----------*/

int printf(const char* format, ...);

typedef struct _sgx_errlist_t {
        sgx_status_t err;
        const char *msg;
        const char *sug; /* Suggestion */
} sgx_errlist_t;

static sgx_errlist_t sgx_errlist[] = {
                {
                                SGX_ERROR_UNEXPECTED,
                                "Unexpected error occurred.",
                                NULL
                },
                {
                                SGX_ERROR_INVALID_PARAMETER,
                                "Invalid parameter.",
                                NULL
                },
                {
                                SGX_ERROR_OUT_OF_MEMORY,
                                "Out of memory.",
                                NULL
                },
                {
                                SGX_ERROR_ENCLAVE_LOST,
                                "Power transition occurred.",
                                "Please refer to the sample \"PowerTransition\" for details."
                },
                {
                                SGX_ERROR_INVALID_ENCLAVE,
                                "Invalid enclave image.",
                                NULL
                },
                {
                                SGX_ERROR_INVALID_ENCLAVE_ID,
                                "Invalid enclave identification.",
                                NULL
                },
                {
                                SGX_ERROR_INVALID_SIGNATURE,
                                "Invalid enclave signature.",
                                NULL
                },
                {
                                SGX_ERROR_OUT_OF_EPC,
                                "Out of EPC memory.",
                                NULL
                },
                {
                                SGX_ERROR_NO_DEVICE,
                                "Invalid SGX device.",
                                "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
                },
                {
                                SGX_ERROR_MEMORY_MAP_CONFLICT,
                                "Memory map conflicted.",
                                NULL
                },
                {
                                SGX_ERROR_INVALID_METADATA,
                                "Invalid enclave metadata.",
                                NULL
                },
                {
                                SGX_ERROR_DEVICE_BUSY,
                                "SGX device was busy.",
                                NULL
                },
                {
                                SGX_ERROR_INVALID_VERSION,
                                "Enclave version was invalid.",
                                NULL
                },
                {
                                SGX_ERROR_INVALID_ATTRIBUTE,
                                "Enclave was not authorized.",
                                NULL
                },
                {
                                SGX_ERROR_ENCLAVE_FILE_ACCESS,
                                "Can't open enclave file.",
                                NULL
                },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
        size_t idx = 0;
        size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

        for (idx = 0; idx < ttl; idx++) {
                if(ret == sgx_errlist[idx].err) {
                        if(NULL != sgx_errlist[idx].sug)
                                printf("Info: %s\n", sgx_errlist[idx].sug);
                        printf("Error: %s\n", sgx_errlist[idx].msg);
                        break;
                }
        }

        if (idx == ttl)
                printf("Error: Unexpected error occurred: %d.\n", ret);
}


/* ---------- ocalls ----------*/

int printf(const char* format, ...) {
        char buf[BUFSIZ] = {'\0'};
        va_list ap;
        va_start(ap, format);
        int r = vsnprintf(buf, BUFSIZ, format, ap);
        va_end(ap);

        sgx_status_t status;
        status = ocall_print_string(buf);
        if (status != SGX_SUCCESS) {
                print_error_message(status);
                r = -1;
        }

        return r;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	int r;
	sgx_status_t status;

	status = ocall_accept(&r, sockfd, addr, *addrlen);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		r = -1;
	}

	return r;
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
	int r;
	sgx_status_t status;

	status = ocall_setsockopt(&r, sockfd, level, optname, optval, optlen);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		r = -1;
	}

	return r;
}

void perror(const char *s) {
	sgx_status_t status;

	status = ocall_perror(s);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
	}
}

void exit(int s) {
	sgx_status_t status;
	status = ocall_exit(s);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
	}

	while (1) {}
}

int close(int fd) {
	int r;
	sgx_status_t status;

	status = ocall_close(&r, fd);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		r = -1;
	}

	return r;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
	ssize_t r;
	sgx_status_t status;

	status = ocall_recv(&r, sockfd, buf, len, flags);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		r = -1;
	}

	return r;
}


ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
	ssize_t r;
	sgx_status_t status;

	status = ocall_send(&r, sockfd, buf, len, flags);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		r = -1;
	}

	return r;

}

int socket(int domain, int type, int protocol) {
	int r;
	sgx_status_t status;

	status = ocall_socket(&r, domain, type, protocol);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		r = -1;
	}

	return r;
}

int bind(int sockfd, const struct sockaddr *addr,
		socklen_t addrlen) {
	int r;
	sgx_status_t status;
	status = ocall_bind(&r, sockfd, addr, addrlen);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		r = -1;
	}

	return r;
}

int listen(int sockfd, int backlog) {
	int r;
	sgx_status_t status;

	status = ocall_listen(&r, sockfd, backlog);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		r = -1;
	}

	return r;
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout) {
	int r;
	sgx_status_t status;

	status = ocall_select(&r, nfds, readfds, writefds, exceptfds, timeout);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		r = -1;
	}

	return r;
}

long int __fdelt_chk (long int d) {
  if (d < 0 || d >= FD_SETSIZE)
    exit(-1);

  return d / __NFDBITS;
}

/* ----------------------------*/

int accept_connection(int sock) {
    // accept the socket
    struct sockaddr_in csin;
    int sinsize = sizeof(csin);
    int current_client_socket_fd = accept(sock, (struct sockaddr*) &csin, (socklen_t*) &sinsize);
    if (current_client_socket_fd == -1) {
        perror("An invalid socket has been accepted: ");
        return -1;
    }

    //TCP NO DELAY
    int flag = 1;
    int result = setsockopt(current_client_socket_fd, IPPROTO_TCP,
                            TCP_NODELAY, (char *) &flag, sizeof(int));
    if (result == -1) {
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

void client_thread(int core, int* done) {
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

    while (!*done) {

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
}

void ecall_start_client_thread(int core, int* done, int _send_packet_size,
	  	int _recv_packet_size, int _reqs_per_conn, int _thr_limit) {
	send_packet_size = _send_packet_size;
	receive_packet_size = _recv_packet_size;
	request_per_connection = _reqs_per_conn;
	throughput_limit = _thr_limit;

	client_thread(core, done);
}

