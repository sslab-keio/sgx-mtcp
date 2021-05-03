/*
 * Copyright 2017 Imperial College London
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <link.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pwd.h>
#include <event.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "enclave_t.h"
#include "sgx_trts.h"

#include "enclaveshim_config.h"
#include "enclaveshim_ocalls.h"

extern int sgx_is_within_enclave(const void*, size_t);

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
        {
                SGX_ERROR_STACK_OVERRUN,
                "Out of stack.",
                NULL
        },
};

FILE* stderr = 0;
FILE* stdin = 0;
FILE* stdout = 0;

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

int puts(const char *s) {
    ocall_println_string(s);
    return 0;
}

int my_vfprintf(FILE *stream, const char *format, va_list ap) {
    fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
    return 0;
}

int my_printf(const char *format, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, format);
    int r = vsnprintf(buf, BUFSIZ, format, ap);
    va_end(ap);

    ocall_print_string(buf);

    return r;
}

int my_fprintf(FILE *stream, const char *format, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, format);
    int r = vsnprintf(buf, BUFSIZ, format, ap);
    va_end(ap);
    ocall_print_string(buf);
    return r;
}

int fprintf(FILE *stream, const char *format, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, format);
    int r = vsnprintf(buf, BUFSIZ, format, ap);
    va_end(ap);
    ocall_print_string(buf);
    return r;
}

void exit(int status) {
    printf("exit(%d)\n", status);
    ocall_exit(status);
    do { } while (1);
}

void __assert_fail(const char *__assertion, const char *__file, unsigned int __line, const char *__function) {
    printf("assert file %s line %d function %s: [%s]\n", __file, __line, __function, __assertion);
    ocall_exit(1);
}

void perror(const char *s) {
	sgx_status_t status;
	status = ocall_perror(s);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
	}
}

FILE *fopen64(const char *path, const char *mode) {
	char* paf;
	if (sgx_is_within_enclave(path, sizeof(*path))) {
		size_t _len_path = path ? strlen(path) + 1 : 0;
		ocall_malloc((void**)&paf, _len_path);
		memcpy(paf, path, _len_path);
	} else {
		paf = (char*)path;
	}

	char* m;
	if (sgx_is_within_enclave(mode, sizeof(*mode))) {
		size_t _len_mode = mode ? strlen(mode) + 1 : 0;
		ocall_malloc((void**)&m, _len_mode);
		memcpy(m, mode, _len_mode);
	} else {
		m = (char*)mode;
	}

	FILE* ret;
	//printf("--> ocall fopen(%s, %s)\n", path, mode);
	sgx_status_t status = ocall_fopen((void**)&ret, (const char*)paf, m);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		ret = 0;
	}

	if (sgx_is_within_enclave(path, sizeof(*path))) {
		ocall_free((void*)paf);
	}

	if (sgx_is_within_enclave(mode, sizeof(*mode))) {
		ocall_free((void*)m);
	}

	return ret;
}

FILE *fopen(const char *path, const char *mode) {
	return fopen64(path, mode);
}

char *fgets(char *s, int size, FILE *stream) {
	char* ret;
	sgx_status_t status;
	status = ocall_fgets(&ret, s, size, stream);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		ret = 0;
	}

	//too verbose printf("ocall fgets(%u, %p) = %p\n", size, stream, ret);
	return ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t ret;
	sgx_status_t status;
	if (sgx_is_within_enclave(ptr, size*nmemb)) {
		status = ocall_fwrite_copy(&ret, ptr, size, nmemb, stream);
	} else {
		status = ocall_fwrite(&ret, ptr, size, nmemb, stream);
	}
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		ret = 0;
	}

	//printf("ocall fwrite(%zu, %p) = %zu\n", size*nmemb, stream, ret);
	return ret;
}

int fclose(FILE *fp) {
	int ret;
	sgx_status_t status;
	status = ocall_fclose(&ret, fp);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		ret = -1;
	}
	//printf("ocall fclose(%p) = %u\n", fp, ret);

	return ret;
}

int fflush(FILE *stream) {
	int ret;
	sgx_status_t status;
	status = ocall_fflush(&ret, stream);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		ret = -1;
	}
	return ret;
}

int open(const char *filename, int flags, ...)
{
	mode_t mode = 0;

	if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}

	my_printf("ocall_open: %s %d %d\n", filename, flags, mode);

	int fd;
	sgx_status_t ret = ocall_open(&fd, filename, flags, mode);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret);
		printf("ocall %s sgx error %d\n", __func__, ret);
		return -1;
	}

	return fd;
}

ssize_t read(int fd, void *buf, size_t count) {
	//printf("ocall %s\n", __func__);
    ssize_t retval;
	sgx_status_t status;
	status = ocall_read(&retval, fd, buf, count);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		printf("ocall %s sgx error %d\n", __func__, status);
		return -1;
	}
	return retval;
}

ssize_t write(int fd, const void *buf, size_t count) {
    ssize_t retval;
	sgx_status_t status;
	status = ocall_write(&retval, fd, buf, count);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		printf("ocall %s sgx error %d\n", __func__, status);
		return -1;
	}
	return retval;
}

int close(int fd) {
    int ret;
    sgx_status_t status;
    status = ocall_close(&ret, fd);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    //printf("ocall close(%p) = %u\n", fd, ret);
    return ret;
}

int ioctl1(int fd, unsigned long request, size_t len, void* ptr) {
    int ret;
    sgx_status_t status;
    status = ocall_ioctl1(&ret, fd, request, len, ptr);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

sighandler_t signal(int signum, sighandler_t handler) {
    //TODO: fix the pointer; we might need a helper function
    void* ret;
    sgx_status_t status;
    //XXX we might need an other argument for the size of ptr
    status = ocall_signal(&ret, signum, handler);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = NULL;
    }
    return (sighandler_t)ret;
}

long syscall1(long number) {
    long ret;
    sgx_status_t status;
    status = ocall_syscall1(&ret, number);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

long sysconf(int name) {
    long ret;
    sgx_status_t status;
    status = ocall_sysconf(&ret, name);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
    int ret;
    sgx_status_t status;
    status = ocall_clock_gettime(&ret, clk_id, tp);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}


int gettimeofday(struct timeval *tv, void* tz) {
    int ret;
    sgx_status_t status;
    status = ocall_gettimeofday(&ret, tv, (struct timezone *)tz);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

int usleep(useconds_t usec) {
    int ret;
    sgx_status_t status;
    status = ocall_usleep(&ret, usec);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

int sched_getcpu(void) {
    int ret;
    sgx_status_t status;
    status = ocall_sched_getcpu(&ret);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

void set_optind(int o) {
    sgx_status_t status;
    status = ocall_set_optind(o);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
    }
}

int mlockall(int flags) {
    int ret;
    sgx_status_t status;
    status = ocall_mlockall(&ret, flags);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

int getopt(int argc, char * const *argv, const char *optstring) {
    int ret;
    sgx_status_t status;
    status = ocall_getopt(&ret, argc, (char **)argv, optstring);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    ocall_getoptarg(&optarg);
    return ret;
}

int getopt_long(int argc, char * const *argv, const char *optstring,
                const struct option *longopts, int *longindex) {
    int ret;
    sgx_status_t status;
    status = ocall_getopt_long(&ret, argc, (char **)argv, optstring, longopts, longindex);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    ocall_getoptarg(&optarg);
    return ret;
}

int sched_yield(void) {
    int ret;
    sgx_status_t status;
    status = ocall_sched_yield(&ret);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

int sscanf(const char *str, const char *format, ...) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int pipe(int pipefd[2]) {
    int ret;
    sgx_status_t status;
    status = ocall_pipe(&ret, pipefd);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

in_addr_t inet_addr(const char *cp) {
    in_addr_t ret;
    sgx_status_t status;
    status = ocall_inet_addr(&ret, cp);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
    }
    return ret;
}


int socket(int domain, int type, int protocol) {
    int ret;
    sgx_status_t status;
    status = ocall_socket(&ret, domain, type, protocol);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

char *inet_ntoa(struct in_addr in) {
    char* ret;
    sgx_status_t status;
    status = ocall_inet_ntoa(&ret, in);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = NULL;
    }
    return ret;
}

int getifaddrs(struct ifaddrs **ifap) {
    int ret;
    sgx_status_t status;
    status = ocall_getifaddrs(&ret, ifap);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

void freeifaddrs(struct ifaddrs *ifa) {
    sgx_status_t status;
    status = ocall_freeifaddrs(ifa);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
    }
}

uid_t geteuid(void) {
    uid_t ret;
    sgx_status_t status;
    status = ocall_geteuid(&ret);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = 0;
    }
    return ret;
}

pid_t getpid(void) {
    pid_t ret;
    sgx_status_t status;
    status = ocall_getpid(&ret);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = 0;
    }
    return ret;
}

void* untrusted_malloc(size_t size) {
    void* ret;
    sgx_status_t status;
    status = ocall_malloc(&ret, size);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = 0;
    }
    return ret;
}

void* untrusted_realloc(void* ptr, size_t size) {
    void* ret;
    sgx_status_t status;
    status = ocall_realloc(&ret, ptr, size);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = 0;
    }
    return ret;
}

void* untrusted_calloc(size_t nmemb, size_t size) {
    void* ret;
    sgx_status_t status;
    status = ocall_calloc(&ret, nmemb, size);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = 0;
    }
    return ret;
}

void untrusted_free(void* ptr) {
    sgx_status_t status;
    status = ocall_free(ptr);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
    }
}

int posix_memalign_on_pagesize(void **memptr, size_t size) {
    int ret;
    sgx_status_t status;
    status = ocall_posix_memalign_on_pagesize(&ret, memptr, size);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

int mlock(const void *addr, size_t len) {
    int ret;
    sgx_status_t status;
    status = ocall_mlock(&ret, addr, len);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

/******************** __CTYPE_B_LOC ********************/

#define X(x) (((x)/256 | (x)*256) % 65536)
static const unsigned short table_1[] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),
        X(0x200),X(0x320),X(0x220),X(0x220),X(0x220),X(0x220),X(0x200),X(0x200),
        X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),
        X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),
        X(0x160),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),
        X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),
        X(0x8d8),X(0x8d8),X(0x8d8),X(0x8d8),X(0x8d8),X(0x8d8),X(0x8d8),X(0x8d8),
        X(0x8d8),X(0x8d8),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),
        X(0x4c0),X(0x8d5),X(0x8d5),X(0x8d5),X(0x8d5),X(0x8d5),X(0x8d5),X(0x8c5),
        X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),
        X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),
        X(0x8c5),X(0x8c5),X(0x8c5),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),
        X(0x4c0),X(0x8d6),X(0x8d6),X(0x8d6),X(0x8d6),X(0x8d6),X(0x8d6),X(0x8c6),
        X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),
        X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),
        X(0x8c6),X(0x8c6),X(0x8c6),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x200),
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};

static const unsigned short *const ptable_1 = table_1+128;

const unsigned short **__ctype_b_loc(void) {
    return (const unsigned short**)&ptable_1;
}

/******************** __CTYPE_B_LOC ********************/

int rte_thread_set_affinity(cpu_set_t *cpusetp) {
    int ret;
    sgx_status_t status;
    status = ocall_rte_thread_set_affinity(&ret, cpusetp);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

unsigned wrapper_rte_lcore_id(void) {
    unsigned ret;
    sgx_status_t status;
    status = ocall_rte_lcore_id(&ret);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

unsigned wrapper_rte_get_master_lcore(void) {
    unsigned ret;
    sgx_status_t status;
    status = ocall_rte_get_master_lcore(&ret);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

unsigned wrapper_rte_socket_id(void) {
    unsigned ret;
    sgx_status_t status;
    status = ocall_rte_socket_id(&ret);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

int wrapper_rte_lcore_index(int lcore_id) {
    int ret;
    sgx_status_t status;
    status = ocall_rte_lcore_index(&ret, lcore_id);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

uint64_t wrapper_rte_rdtsc(void) {
    uint64_t ret;
    sgx_status_t status;
    status = ocall_rte_rdtsc(&ret);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = 0;
    }
    return ret;
}

int ecall_rte_eal_remote_launch_call_callback(void *f, void* arg) {
    int (*start_routine)(void *) = (int (*)(void *))f;
    return start_routine(arg);
}

int rte_eal_remote_launch(int (*f)(void *), void *arg, unsigned slave_id) {
    int ret;
    sgx_status_t status;
    status = ocall_rte_eal_remote_launch(&ret, (void*)f, arg, slave_id);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = 0;
    }
    return ret;
}

int rte_eal_wait_lcore(unsigned slave_id) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return 0;
}

int rte_eal_init(int argc, char **argv) {
    int ret, i, len;
    sgx_status_t status;

    char **un_argv = untrusted_calloc(sizeof(*un_argv), argc);
    for (i=0; i<argc; i++) {
        len = strlen(argv[i]);
		  un_argv[i] = untrusted_malloc(sizeof(**un_argv) * (len+1));
		  memcpy(un_argv[i], argv[i], len);
		  un_argv[i][len] = '\0';
    }

    status = ocall_rte_eal_init(&ret, argc, un_argv);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }

    for (i=0; i<argc; i++) {
        len = strlen(un_argv[i]);
        if (len > 0) {
            untrusted_free(un_argv[i]);
        }
    }
    untrusted_free(un_argv);

    return ret;
}

uint16_t rte_eth_dev_count_avail(void) {
    uint16_t ret;
    sgx_status_t status;
    status = ocall_rte_eth_dev_count_avail(&ret);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

void* rte_calloc_socket(const char *type, size_t num, size_t size, unsigned align, int socket) {
    void* ret;
    sgx_status_t status;
    status = ocall_rte_calloc_socket(&ret, type, num, size, align, socket);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = NULL;
    }
    return ret;
}

void* rte_malloc_socket(const char *type, size_t size, unsigned int align, int socket_arg) {
    void* ret;
    sgx_status_t status;
    status = ocall_rte_malloc_socket(&ret, type, size, align, socket_arg);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = NULL;
    }
    return ret;
}

void* rte_zmalloc_socket(const char *type, size_t size, unsigned align, int socket) {
    void* ret;
    sgx_status_t status;
    status = ocall_rte_calloc_socket(&ret, type, 1, size, align, socket);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = NULL;
    }
    return ret;
}

struct rte_ring* rte_ring_create(const char *name, unsigned count, int socket_id, unsigned flags) {
    void *ret;
    sgx_status_t status;
    status = ocall_rte_ring_create(&ret, name, count, socket_id, flags);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = NULL;
    }
    return (struct rte_ring*)ret;
}

void rte_free(void *addr) {
    sgx_status_t status;
    status = ocall_rte_free(addr);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
    }
}

void rte_eth_macaddr_get(uint16_t port_id, struct ether_addr *mac_addr) {
    sgx_status_t status;
    status = ocall_rte_eth_macaddr_get(port_id, mac_addr);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
    }
}

void sgx_dpdk_init_handle(struct mtcp_thread_context *ctxt) {
    sgx_status_t status;
    status = ocall_dpdk_init_handle(ctxt);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
    }
}

int sgx_dpdk_send_pkts(struct mtcp_thread_context *ctxt, int ifidx) {
    int ret;
    sgx_status_t status;
    status = ocall_dpdk_send_pkts(&ret, ctxt, ifidx);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

int sgx_dpdk_send_merged_pkts(struct mtcp_thread_context *ctxt, int ifidx) {
    int ret;
    sgx_status_t status;
    status = ocall_dpdk_send_merged_pkts(&ret, ctxt, ifidx);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

int32_t sgx_dpdk_recv_pkts(struct mtcp_thread_context *ctxt, int ifidx) {
    int32_t ret;
    sgx_status_t status;
    status = ocall_dpdk_recv_pkts(&ret, ctxt, ifidx);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

int32_t sgx_dpdk_recv_pkts_and_gettimeofday(struct mtcp_thread_context *ctxt, int ifidx, struct timeval* cur_ts) {
    int32_t ret;
    sgx_status_t status;
    status = ocall_dpdk_recv_pkts_and_gettimeofday(&ret, ctxt, ifidx, cur_ts);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

int32_t sgx_dpdk_send_pkts_and_dpdk_recv_pkts_and_gettimeofday(struct mtcp_thread_context *ctxt, int ifidx, struct timeval* cur_ts) {
    int32_t ret;
    sgx_status_t status;
    status = ocall_dpdk_send_pkts_and_dpdk_recv_pkts_and_gettimeofday(&ret, ctxt, ifidx, cur_ts);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

int32_t sgx_dpdk_send_merged_pkts_and_dpdk_recv_pkts_and_gettimeofday(struct mtcp_thread_context *ctxt, int ifidx, struct timeval* cur_ts) {
    int32_t ret;
    sgx_status_t status;
    status = ocall_dpdk_send_merged_pkts_and_dpdk_recv_pkts_and_gettimeofday(&ret, ctxt, ifidx, cur_ts);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

void sgx_dpdk_destroy_handle(struct mtcp_thread_context *ctxt) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
}

void sgx_check_all_ports_link_status(uint8_t port_num, uint32_t port_mask) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
}

void sgx_dpdk_load_module(struct mtcp_config conf, int num_devices_attached, int devices_attached[MAX_DEVICES]) {
    sgx_status_t status;
    status = ocall_dpdk_load_module(conf, num_devices_attached, devices_attached);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
    }
}

void sgx_get_dev_info(int nif, char** driver_name, uint64_t* tx_offload_capa, uint64_t* rx_offload_capa) {
    sgx_status_t status;
    status = ocall_dpdk_get_dev_info(nif, driver_name, tx_offload_capa, rx_offload_capa);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
    }
}

enum rte_proc_type_t eal_proc_type_detect(void) {
    enum rte_proc_type_t ret;
    sgx_status_t status;
    status = ocall_eal_proc_type_detect(&ret);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

void set_lcore_config(int master, int ret, enum rte_lcore_state_t state) {
    sgx_status_t status;
    status = ocall_set_lcore_config(master, ret, state);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
    }
}

char *strsignal(int sig) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return NULL;
}

int getrusage(int who, struct rusage *usage) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

int raise(int sig) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

int listen(int s, int backlog) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    //TODO: ocall
	 // It is called by lighttpd but shouldn't be because we use mtcp
    //printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

ssize_t wrapper_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

uid_t getuid(void) {
    uid_t ret;
    sgx_status_t status;
    status = ocall_getuid(&ret);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = 0;
    }
    return ret;
}

int setuid(uid_t uid) {
    int ret;
    sgx_status_t status;
    status = ocall_setuid(&ret, uid);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = 0;
    }
    return ret;
}

gid_t getgid(void) {
    gid_t ret;
    sgx_status_t status;
    status = ocall_getgid(&ret);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = 0;
    }
    return ret;
}

int setgid(gid_t gid) {
    int ret;
    sgx_status_t status;
    status = ocall_setgid(&ret, gid);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = 0;
    }
    return ret;
}

mode_t umask(mode_t mask) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

int unlink(const char *pathname) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

int rename(const char *oldpath, const char *newpath) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

time_t time(time_t *t) {
	time_t ret;
	sgx_status_t status;
	status = ocall_time(&ret, t);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		ret = -1;
	}
	return ret;
}

int kill(pid_t pid, int sig) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

int fcntl(int fd, int cmd, ...) {
	// get 3rd argument
	// this might fail if no such argument exist?
	int arg = 0;
	va_list ap;
	va_start(ap, cmd);
	arg = va_arg(ap, int);
	va_end(ap);

	sgx_status_t status;
	int ret = 0;
	status = ocall_fcntl(&ret, fd, cmd, arg);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
	}
	return ret;
}

int access(const char *pathname, int mode) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

int sigignore(int sig) {
    int ret;
    sgx_status_t status;
    status = ocall_sigignore(&ret, sig);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

pid_t setsid(void) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

void setbuf(FILE *stream, char *buf) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
}

int wrapper_stat(const char *pathname, struct stat *statbuf) {
    int ret;
    sgx_status_t status;
    status = ocall_wrapper_stat(&ret, pathname, statbuf);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

int wrapper_lstat(const char *path, struct stat *sb) {
    int ret;
    sgx_status_t status;
    status = ocall_wrapper_lstat(&ret, path, sb);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res) {
    int ret;
    sgx_status_t status;
    status = ocall_getaddrinfo(&ret, node, service, hints, res);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

void freeaddrinfo(struct addrinfo *res) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
}

const char *gai_strerror(int errcode) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return NULL;
}

int dup(int oldfd) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

int dup2(int oldfd, int newfd) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

char *strdup(const char *s) {
    char *ret;
    sgx_status_t status;
    status = ocall_strdup(&ret, s);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = NULL;
    }
    return ret;
}

int getsubopt(char **optionp, char * const *tokens, char **valuep) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

struct passwd *getpwnam(const char *name) {
    struct passwd *ret;
    sgx_status_t status;
    status = ocall_getpwnam(&ret, name);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = NULL;
    }
    return ret;
}

int getgroups(int size, gid_t list[]) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

int setgroups(size_t size, const gid_t *list) {
    int ret;
    sgx_status_t status;
    status = ocall_setgroups(&ret, size, list);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
}

int madvise(void * start , size_t length , int advice) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

int chdir(const char *path) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

pid_t fork(void) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

int posix_memalign(void **memptr, size_t alignment, size_t size) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

int wrapper_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

int wrapper_getrlimit(int resource, struct rlimit *rlim) {
    int ret;
    sgx_status_t status;
    status = ocall_getrlimit(&ret, resource, rlim);
    if (status != SGX_SUCCESS) {
      print_error_message(status);
      ret = -1;
    }

    return ret;
}

int wrapper_setrlimit(int resource, const struct rlimit *rlim) {
    int ret;
    sgx_status_t status;
    status = ocall_setrlimit(&ret, resource, rlim);
    if (status != SGX_SUCCESS) {
      print_error_message(status);
      ret = -1;
    }

    return ret;
}

// libevent
int event_add (struct event *ev, const struct timeval *timeout) {
    int ret;
    sgx_status_t status;
    status = ocall_event_add(&ret, ev, timeout);
    if (status != SGX_SUCCESS) {
      print_error_message(status);
      ret = -1;
    }

    return ret;
}

int event_del(struct event *ev) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return -1;
}

void event_set (struct event *ev, int fd, short event, void(*cb)(int, short, void *), void *arg) {
    sgx_status_t status;
    status = ocall_event_set(ev, fd, event, cb, arg);
    if (status != SGX_SUCCESS) {
      print_error_message(status);
    }
}

int event_base_set(struct event_base *base, struct event *ev) {
    int ret;
    sgx_status_t status;
    status = ocall_event_base_set(&ret, base, ev);
    if (status != SGX_SUCCESS) {
      print_error_message(status);
      ret = -1;
    }

    return ret;
}

const char * event_get_version(void) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return NULL;
}

struct event_config * event_config_new(void) {
    struct event_config *ret;
    sgx_status_t status;
    status = ocall_event_config_new(&ret);
    if (status != SGX_SUCCESS) {
      print_error_message(status);
      ret = NULL;
    }

    return ret;
}

int event_config_set_flag(struct event_config *cfg, int flag) {
    int ret;
    sgx_status_t status;
    status = ocall_event_config_set_flag(&ret, cfg, flag);
    if (status != SGX_SUCCESS) {
      print_error_message(status);
      ret = -1;
    }

    return ret;
}

struct event_base * event_base_new_with_config(const struct event_config *cfg) {
    struct event_base *ret;
    sgx_status_t status;
    status = ocall_event_base_new_with_config(&ret, cfg);
    if (status != SGX_SUCCESS) {
      print_error_message(status);
      ret = NULL;
    }

    return ret;
}

void event_config_free(struct event_config *cfg) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
}

int event_base_loop(struct event_base *base, int flags) {
    int ret;
    sgx_status_t status;
    status = ocall_event_base_loop(&ret, base, flags);
    if (status != SGX_SUCCESS) {
      print_error_message(status);
      ret = -1;
    }

    return ret;
}

void event_base_free(struct event_base *base) {
    //TODO: ocall
    printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
}

// lighttpd
int chroot(const char *path) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

int closedir(DIR *dirp) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

void closelog(void) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

int epoll_create(int size) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

int execl(const char *path, const char *arg, ... /* (char  *) NULL */) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

char *getcwd(char *buf, size_t size) {
    char* ret;
    sgx_status_t status;
    status = ocall_getcwd(&ret, buf, size);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = NULL;
    }
    return ret;
}

gid_t getegid(void) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

struct group *getgrnam(const char *name) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return NULL;
}

struct hostent *gethostbyname(const char *name) {
    struct hostent* ret;
    sgx_status_t status;
    status = ocall_gethostbyname(&ret, name);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = NULL;
    }
    return ret;
}

struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return NULL;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

struct tm *gmtime(const time_t *timep) {
	struct tm* ret;
	sgx_status_t status;
	status = ocall_gmtime(&ret, timep);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		ret = NULL;
	}
	return ret;
}

int inet_aton(const char *cp, struct in_addr *inp) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

int initgroups(const char *user, gid_t group) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

struct tm *localtime(const time_t *timep) {
    struct tm* ret;
    sgx_status_t status;
    status = ocall_localtime(&ret, timep);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = NULL;
    }
    return ret;
}

struct tm *localtime_r(const time_t *timep, struct tm *result) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return NULL;
}

time_t mktime(struct tm *tm) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

off64_t lseek64(int fd, off64_t offset, int whence) {
	sgx_status_t status;
	off64_t ret = NULL;
	status = ocall_lseek64(&ret, fd, offset, whence);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
	}
	return ret;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	sgx_status_t status;
	void* ret = NULL;
	status = ocall_mmap(&ret, addr, length, prot, flags, fd, offset);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
	}
	return ret;
}

void *wrapper_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	return mmap(addr, length, prot, flags, fd, offset);
}

int munmap(void *addr, size_t length) {
	sgx_status_t status;
	int ret = 0;
	status = ocall_munmap(&ret, addr, length);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
	}
	return ret;
}

DIR *opendir(const char *name) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return NULL;
}

void openlog(const char *ident, int option, int facility) {
    sgx_status_t status;
    status = ocall_openlog(ident, option, facility);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
    }
}

long pathconf(const char *path, int name) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

int prctl(int option, ...) {
//int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}


int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}


char *setlocale(int category, const char *locale) {
    char* ret;
    sgx_status_t status;
    status = ocall_setlocale(&ret, category, locale);
    if (status != SGX_SUCCESS) {
      print_error_message(status);
      ret = NULL;
    }

    return ret;
}


int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}


int sigemptyset(sigset_t *set) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}


unsigned int sleep(unsigned int seconds) {
	return usleep(seconds*1000*1000);
}


char *strptime(const char *s, const char *format, struct tm *tm) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return NULL;
}


void tzset (void) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
}

pid_t wait(int *wstatus) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

pid_t waitpid(pid_t pid, int *wstatus, int options) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

int open64(const char *filename, int flags, ...) {
	mode_t mode = 0;

	if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}

	int fd;
	sgx_status_t ret = ocall_open64(&fd, filename, flags, mode);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret);
		printf("ocall %s sgx error %d\n", __func__, ret);
		return -1;
	}

	return fd;
}

struct dirent *wrapper_readdir(DIR *dirp) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return NULL;
}

int wrapper_mkstemp(char *template) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

ssize_t wrapper_sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

long int __fdelt_chk (long int __d) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

int wrapper_putc(int c, FILE *stream) {
	//TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

int wrapper_syslog(int priority, const char *format, ...) {
   //TODO: ocall
	printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
	return 0;
}

int __getpagesize(void) {
	int ret;
	sgx_status_t status;
	status = ocall__getpagesize(&ret);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		ret = -1;
	}

	return ret;
}
