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
#include <pwd.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "sgx_urts.h"

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#define TOKEN_FILENAME   "enclave.token"
#define ENCLAVE_FILENAME "enclave.signed.so"

#define MAX_PATH 256

#ifndef MAX_CPUS
#define MAX_CPUS    16
#endif

/* Global EID shared by multiple threads */
static sgx_enclave_id_t global_eid = 0;

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


static pthread_t app_thread[MAX_CPUS];
static int done[MAX_CPUS];

static int num_cores;
static int send_packet_size = 0;
static int receive_packet_size = 0;
static int request_per_connection = 1;
static int throughput_limit = -1; // MB

/********** Enclave stuff **********/

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret, const char* fn)
{
        size_t idx = 0;
        size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

        for (idx = 0; idx < ttl; idx++) {
                if(ret == sgx_errlist[idx].err) {
                        if(NULL != sgx_errlist[idx].sug)
                                printf("Info: %s from %s\n", sgx_errlist[idx].sug, fn);
                        printf("Error: %s from %s\n", sgx_errlist[idx].msg, fn);
                        break;
                }
        }

        if (idx == ttl)
                printf("Error: Unexpected error occurred: %d from %s.\n", ret, fn);
}
/* Initialize the enclave:
 *    Step 1: try to retrieve the launch token saved by last transaction
 *     Step 2: call sgx_create_enclave to initialize an enclave instance
 *    Step 3: save the launch token if it is updated
 */
int _initialize_enclave(void)
{
	char token_path[MAX_PATH] = {'\0'};
	sgx_launch_token_t token = {0};
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;

	/* Step 1: try to retrieve the launch token saved by last transaction
	 *           *          *         if there is no token, then create a new one.
	 *                   *                   */
	/* try to get the token saved in $HOME */
	const char *home_dir = getpwuid(getuid())->pw_dir;

	if (home_dir != NULL &&
			(strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
		/* compose the token path */
		strncpy(token_path, home_dir, strlen(home_dir));
		strncat(token_path, "/", strlen("/"));
		strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
	} else {
		/* if token path is too long or $HOME is NULL */
		strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
	}

	FILE *fp = fopen(token_path, "rb");
	if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
		printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
	}
	if (fp != NULL) {
		/* read the token from saved file */
		size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
		}
	}

	/* Step 2: call sgx_create_enclave to initialize an enclave instance */
	/* Debug Support: set 2nd parameter to 1 */
	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		if (fp != NULL) fclose(fp);
		return -1;
	}

	/* Step 3: save the launch token if it is updated */
	if (updated == FALSE || fp == NULL) {
		/* if the token is not updated, or file handler is invalid, do not perform saving */
		if (fp != NULL) fclose(fp);
		return 0;
	 }

	 /* reopen the file with write capablity */
	 fp = freopen(token_path, "wb", fp);
	 if (fp == NULL) return 0;
	 size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
	 if (write_num != sizeof(sgx_launch_token_t))
		 printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
	 fclose(fp);
	 return 0;
}

void initalize_enclave(void) {
        if (_initialize_enclave() < 0) {
                printf("Enclave initialization error!\n");
                exit(-1);
        }
}

/********** Ocalls **********/

void ocall_print_string(const char* str) {
	printf("%s", str);
	fflush(NULL);
}

void ocall_println_string(const char* str) {
	printf("%s\n", str);
	fflush(NULL);
}

void ocall_exit(int s) {
	exit(s);
	while (1) {};
}

int ocall_close(int fd) {
	int ret = close(fd);
	return ret;
}

int ocall_accept(int sockfd, struct sockaddr *addr, socklen_t addrlen) {
	return accept(sockfd, addr, &addrlen);
}

int ocall_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
	return setsockopt(sockfd, level, optname, optval, optlen);

}

void ocall_perror(const char *s) {
	perror(s);
}

ssize_t ocall_recv(int sockfd, void *buf, size_t len, int flags){
	return recv(sockfd, buf, len, flags);
}

ssize_t ocall_send(int sockfd, const void *buf, size_t len, int flags) {
	return send(sockfd, buf, len, flags);
}


int ocall_socket(int domain, int type, int protocol) {
	return socket(domain, type, protocol);
}


int ocall_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	return bind(sockfd, addr, addrlen);
}


int ocall_listen(int sockfd, int backlog) {
	return listen(sockfd, backlog);
}


int ocall_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
	return select(nfds, readfds, writefds, exceptfds, timeout);
}

/********** The app **********/

void* client_thread(void *arg) {
    int core = *(int *)arg;

	 sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	 ret = ecall_start_client_thread(global_eid, core, &done[core], send_packet_size, receive_packet_size, request_per_connection, throughput_limit);
	 if (ret != SGX_SUCCESS) {
		 print_error_message(ret, __func__);
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

	 initalize_enclave();

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

	 if (global_eid != 0) {
		 sgx_destroy_enclave(global_eid);
	 }

    return 0;
}
