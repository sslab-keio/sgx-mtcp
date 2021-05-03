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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sched.h>
#include <sys/mman.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/resource.h>
#include <getopt.h>
#include <pwd.h>
#include <event.h>
#include <locale.h>

#include "ocalls.h"
#include "enclaveshim_log.h"
#include "enclaveshim_ecalls.h"

#include "tcp_in.h"

#ifndef DISABLE_DPDK
enum rte_proc_type_t eal_proc_type_detect(void);
/**
 * DPDK's RTE consumes some huge pages for internal bookkeeping.
 * Therefore, it is not always safe to reserve the exact amount
 * of pages for our stack (e.g. dividing requested mem, in MB, by
 * (1<<20) would be insufficient). Hence, the following value.
 */
#define RTE_SOCKET_MEM_SHIFT		((1<<19)|(1<<18))
#endif

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
}

void* ocall_fopen(const char *path, const char *mode) {
    log_enter_ocall(__func__);
    FILE* f = fopen(path, mode);
    log_exit_ocall(__func__);
    return (void*)f;
}

char *ocall_fgets(char *s, int size, void *stream) {
    log_enter_ocall(__func__);
    char* ret = fgets(s, size, (FILE*)stream);
    log_exit_ocall(__func__);
    return ret;
}

size_t _ocall_fwrite(const void *ptr, size_t size, size_t nmemb, void *stream) {
    log_enter_ocall(__func__);
    size_t ret;
    if (!stream) {
        size_t i;
        for (i=0; i<size*nmemb; i++) {
            printf("%c", *((char*)ptr+i));
        }
        fflush(NULL);
        ret = size*nmemb;
    } else {
        ret = fwrite(ptr, size, nmemb, (FILE*)stream);
    }
    log_exit_ocall(__func__);
    return ret;
}

size_t ocall_fwrite(const void *ptr, size_t size, size_t nmemb, void *stream) {
    return _ocall_fwrite(ptr, size, nmemb, stream);
}

size_t ocall_fwrite_copy(const void *ptr, size_t size, size_t nmemb, void *stream) {
    return _ocall_fwrite(ptr, size, nmemb, stream);
}

int ocall_fclose(void* fp) {
    log_enter_ocall(__func__);
    int ret = fclose((FILE*)fp);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_fflush(void* stream) {
    return fflush((FILE*)stream);
}

int ocall_open(const char *filename, int flags, mode_t mode) {
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        return open(filename, flags, mode);
    } else {
        return open(filename, flags);
    }
}
int ocall_open64(const char *filename, int flags, mode_t mode) {
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        return open64(filename, flags, mode);
    } else {
        return open64(filename, flags);
    }
}

ssize_t ocall_read(int fd, void *buf, size_t count) {
    log_enter_ocall(__func__);
    ssize_t ret = read(fd, buf, count);
    log_exit_ocall(__func__);
    return ret;
}

ssize_t ocall_write(int fd, const void *buf, size_t count) {
    log_enter_ocall(__func__);
    ssize_t ret = write(fd, buf, count);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_close(int fd) {
    log_enter_ocall(__func__);
    int ret = close(fd);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_pipe(int pipefd[2]) {
    log_enter_ocall(__func__);
    int ret = pipe(pipefd);
    log_exit_ocall(__func__);
    return ret;
}

void* ocall_malloc(size_t size) {
    log_enter_ocall(__func__);
    void* ret = malloc(size);
    log_exit_ocall(__func__);
    return ret;
}

void* ocall_realloc(void* ptr, size_t size) {
    log_enter_ocall(__func__);
    void* ret = realloc(ptr, size);
    log_exit_ocall(__func__);
    return ret;
}

void* ocall_calloc(size_t nmemb, size_t size) {
    log_enter_ocall(__func__);
    void* ret = calloc(nmemb, size);
    log_exit_ocall(__func__);
    return ret;
}

void ocall_free(void* ptr) {
    log_enter_ocall(__func__);
    free(ptr);
    log_exit_ocall(__func__);
}

int ocall_ioctl1(int fd, unsigned long request, size_t len, void* ptr) {
    log_enter_ocall(__func__);
    int ret = ioctl(fd, request, ptr);
    log_exit_ocall(__func__);
    return ret;
}

void* ocall_signal(int signum, void* handler) {
    log_enter_ocall(__func__);
    void* ret = signal(signum, handler);
    log_exit_ocall(__func__);
    return ret;
}

long ocall_syscall1(long number) {
    log_enter_ocall(__func__);
    long ret = syscall(number);
    log_exit_ocall(__func__);
    return ret;
}

long ocall_sysconf(int name) {
    log_enter_ocall(__func__);
    long ret = sysconf(name);
    log_exit_ocall(__func__);
    return ret;
}

void ocall_perror(const char *s) {
    log_enter_ocall(__func__);
    perror(s);
    log_exit_ocall(__func__);
}

int ocall_clock_gettime(clockid_t clk_id, struct timespec *tp) {
    log_enter_ocall(__func__);
    int ret = clock_gettime(clk_id, tp);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_gettimeofday(struct timeval *tv, struct timezone *tz) {
    log_enter_ocall(__func__);
    int ret = gettimeofday(tv, tz);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_usleep(useconds_t usec) {
    log_enter_ocall(__func__);
    int ret = usleep(usec);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_sched_getcpu(void) {
    log_enter_ocall(__func__);
    int ret = sched_getcpu();
    log_exit_ocall(__func__);
    return ret;
}

void ocall_set_optind(int o) {
    log_enter_ocall(__func__);
    optind = 0;
    log_exit_ocall(__func__);
}

int ocall_mlockall(int flags) {
    log_enter_ocall(__func__);
    int ret = mlockall(flags);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_getopt(int argc, char** argv, const char *optstring) {
    log_enter_ocall(__func__);
    int ret = getopt(argc, (char * const *)argv, optstring);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_getopt_long(int argc, char** argv, const char *optstring,
                const struct option *longopts, int *longindex) {
    log_enter_ocall(__func__);
    int ret = getopt_long(argc, (char * const *)argv, optstring, longopts, longindex);
    log_exit_ocall(__func__);
    return ret;
}

char* ocall_getoptarg() {
    log_enter_ocall(__func__);
    log_exit_ocall(__func__);
    return optarg;
}

int ocall_sched_yield(void) {
    log_enter_ocall(__func__);
    int ret = sched_yield();
    log_exit_ocall(__func__);
    return ret;
}

in_addr_t ocall_inet_addr(const char *cp) {
    log_enter_ocall(__func__);
    in_addr_t ret = inet_addr(cp);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_socket(int domain, int type, int protocol) {
    log_enter_ocall(__func__);
    int ret = socket(domain, type, protocol);
    log_exit_ocall(__func__);
    return ret;
}

char *ocall_inet_ntoa(struct in_addr in) {
    log_enter_ocall(__func__);
    char* ret = inet_ntoa(in);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_getifaddrs(struct ifaddrs **ifap) {
    log_enter_ocall(__func__);
    int ret = getifaddrs(ifap);
    log_exit_ocall(__func__);
    return ret;
}

void ocall_freeifaddrs(struct ifaddrs *ifa) {
    log_enter_ocall(__func__);
    freeifaddrs(ifa);
    log_exit_ocall(__func__);
}

uid_t ocall_getuid(void) {
    log_enter_ocall(__func__);
    uid_t ret = getuid();
    log_exit_ocall(__func__);
    return ret;
}

uid_t ocall_geteuid(void) {
    log_enter_ocall(__func__);
    uid_t ret = geteuid();
    log_exit_ocall(__func__);
    return ret;
}

pid_t ocall_getpid(void) {
    log_enter_ocall(__func__);
    pid_t ret = getpid();
    log_exit_ocall(__func__);
    return ret;
}

int ocall_posix_memalign_on_pagesize(void **memptr, size_t size) {
    log_enter_ocall(__func__);
    int ret = posix_memalign(memptr, getpagesize(), size);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_mlock(const void *addr, size_t len) {
    log_enter_ocall(__func__);
    int ret = mlock(addr, len);
    log_exit_ocall(__func__);
    return ret;
}

/* ========== thread ocalls ========== */

int ocall_pthread_create(thread_t *thread, const thread_attr_t *attr, void *start_routine, void *arg) {
    log_enter_ocall(__func__);
    int ret = enclaveshim_thread_create(thread, attr, start_routine, arg);
    log_exit_ocall(__func__);
    return ret;
}

void ocall_pthread_exit(void *ret) {
    log_enter_ocall(__func__);
    pthread_exit(ret);
    log_exit_ocall(__func__);
}

int ocall_pthread_join(thread_t th, void **thread_return) {
    log_enter_ocall(__func__);
    int ret = pthread_join(th, thread_return);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_pthread_setspecific(thread_key_t key, const void *ptr) {
    log_enter_ocall(__func__);
    int ret = pthread_setspecific(key, ptr);
    log_exit_ocall(__func__);
    return ret;
}

void* ocall_pthread_getspecific(thread_key_t key) {
    log_enter_ocall(__func__);
    void *ret = pthread_getspecific(key);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_pthread_key_create(thread_key_t *key, void *destr_function) {
    log_enter_ocall(__func__);
    int ret = pthread_key_create(key, (void (*)(void *))destr_function);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_sem_init(sem_t *sem, int pshared, unsigned int value) {
    log_enter_ocall(__func__);
    int ret = sem_init(sem, pshared, value);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_sem_destroy(sem_t *sem) {
    log_enter_ocall(__func__);
    int ret = sem_destroy(sem);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_sem_wait(sem_t *sem) {
    log_enter_ocall(__func__);
    int ret = sem_wait(sem);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_sem_post(sem_t *sem) {
    log_enter_ocall(__func__);
    int ret = sem_post(sem);
    log_exit_ocall(__func__);
    return ret;
}

/* ========== DPDK ocalls ========== */


void ocall_set_lcore_config(int master, int ret, enum rte_lcore_state_t state) {
    log_enter_ocall(__func__);
    lcore_config[master].ret = ret;
    lcore_config[master].state = state;
    log_exit_ocall(__func__);
}

int ocall_rte_eal_init(int argc, char **argv) {
    log_enter_ocall(__func__);
    int ret = rte_eal_init(argc, argv);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_rte_eal_remote_launch(void* f, void *arg, unsigned slave_id) {
    log_enter_ocall(__func__);
    int (*fake_callback)(void*) = (int (*)(void *))enclaveshim_register_rte_eal_remote_launch_callback(f);
    int ret = rte_eal_remote_launch(fake_callback, arg, slave_id);
    log_exit_ocall(__func__);
    return ret;
}

uint16_t ocall_rte_eth_dev_count_avail(void) {
    log_enter_ocall(__func__);
    uint16_t ret = rte_eth_dev_count_avail();
    log_exit_ocall(__func__);
    return ret;
}

void* ocall_rte_calloc_socket(const char *type, size_t num, size_t size, unsigned align, int socket) {
    log_enter_ocall(__func__);
    void *ret = rte_calloc_socket(type, num, size, align, socket);
    log_exit_ocall(__func__);
    return ret;
}

void* ocall_rte_malloc_socket(const char *type, size_t size, unsigned int align, int socket_arg) {
    log_enter_ocall(__func__);
    void *ret = rte_malloc_socket(type, size, align, socket_arg);
    log_exit_ocall(__func__);
    return ret;
}

void* ocall_rte_ring_create(const char *name, unsigned count, int socket_id, unsigned flags) {
    log_enter_ocall(__func__);
    struct rte_ring *ret = rte_ring_create(name, count, socket_id, flags);
    log_exit_ocall(__func__);
    return (void*)ret;
}

uint64_t ocall_rte_rdtsc(void) {
    log_enter_ocall(__func__);
    uint64_t ret = rte_rdtsc();
    log_exit_ocall(__func__);
    return ret;
}

void ocall_rte_free(void *addr) {
    log_enter_ocall(__func__);
    rte_free(addr);
    log_exit_ocall(__func__);
}

void ocall_rte_eth_macaddr_get(uint16_t port_id, struct ether_addr *mac_addr) {
    log_enter_ocall(__func__);
    rte_eth_macaddr_get(port_id, mac_addr);
    log_exit_ocall(__func__);
}

enum rte_proc_type_t ocall_eal_proc_type_detect(void) {
    log_enter_ocall(__func__);
    enum rte_proc_type_t ret = eal_proc_type_detect();
    log_exit_ocall(__func__);
    return ret;
}

int ocall_rte_thread_set_affinity(cpu_set_t *cpusetp) {
    log_enter_ocall(__func__);
    int ret = rte_thread_set_affinity(cpusetp);
    log_exit_ocall(__func__);
    return ret;
}

unsigned ocall_rte_lcore_id(void) {
    log_enter_ocall(__func__);
    unsigned ret = rte_lcore_id();
    log_exit_ocall(__func__);
    return ret;
}

unsigned ocall_rte_get_master_lcore(void) {
    log_enter_ocall(__func__);
    unsigned ret = rte_get_master_lcore();
    log_exit_ocall(__func__);
    return ret;
}

unsigned ocall_rte_socket_id(void) {
    log_enter_ocall(__func__);
    unsigned ret = rte_socket_id();
    log_exit_ocall(__func__);
    return ret;
}

int ocall_rte_lcore_index(int lcore_id) {
    log_enter_ocall(__func__);
    int ret = rte_lcore_index(lcore_id);
    log_exit_ocall(__func__);
    return ret;
}

struct mtcp_config CONFIG = {
    /* set default configuration */
    .max_concurrency  =			10000,
    .max_num_buffers  =			10000,
    .rcvbuf_size	  =			-1,
    .sndbuf_size	  =			-1,
    .tcp_timeout	  =			TCP_TIMEOUT,
    .tcp_timewait	  =			TCP_TIMEWAIT,
    .num_mem_ch	  =			0,
#ifdef ENABLE_ONVM
    .onvm_inst	  =			(uint16_t) -1,
	.onvm_dest	  =			(uint16_t) -1,
	.onvm_serv	  =			(uint16_t) -1
#endif
};

int num_devices_attached;
int devices_attached[MAX_DEVICES];

void ocall_dpdk_load_module(struct mtcp_config conf, int _num_devices_attached, int* _devices_attached) {
    CONFIG = conf;
    num_devices_attached = _num_devices_attached;
    int i;
    for (i=0; i<MAX_DEVICES; i++) {
        devices_attached[i] = _devices_attached[i];
    }

    log_enter_ocall(__func__);
    dpdk_module_func.load_module();
    log_exit_ocall(__func__);
}

void ocall_dpdk_init_handle(struct mtcp_thread_context *ctxt) {
    log_enter_ocall(__func__);
    dpdk_module_func.init_handle(ctxt);
    log_exit_ocall(__func__);
}

int ocall_dpdk_send_pkts(struct mtcp_thread_context *ctxt, int ifidx) {
    log_enter_ocall(__func__);
    int ret = dpdk_module_func.send_pkts(ctxt, ifidx);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_dpdk_send_merged_pkts(struct mtcp_thread_context *ctxt, int ifidx) {
    log_enter_ocall(__func__);
    int ret = dpdk_module_func.send_merged_pkts(ctxt, ifidx);
    log_exit_ocall(__func__);
    return ret;
}

int32_t ocall_dpdk_recv_pkts(struct mtcp_thread_context *ctxt, int ifidx) {
    log_enter_ocall(__func__);
    int32_t ret = dpdk_module_func.recv_pkts(ctxt, ifidx);
    log_exit_ocall(__func__);
    return ret;
}

void ocall_dpdk_get_dev_info(int nif, char** driver_name, uint64_t* tx_offload_capa, uint64_t* rx_offload_capa) {
    log_enter_ocall(__func__);
    dpdk_module_get_dev_info(nif, driver_name, tx_offload_capa, rx_offload_capa);
    log_exit_ocall(__func__);
}

int32_t ocall_dpdk_recv_pkts_and_gettimeofday(struct mtcp_thread_context *ctxt, int ifidx, struct timeval* cur_ts) {
    log_enter_ocall(__func__);
    int32_t ret = dpdk_module_func.recv_pkts_and_gettimeofday(ctxt, ifidx, cur_ts);
    log_exit_ocall(__func__);
    return ret;
}

int32_t ocall_dpdk_send_pkts_and_dpdk_recv_pkts_and_gettimeofday(struct mtcp_thread_context *ctxt, int ifidx, struct timeval* cur_ts) {
    log_enter_ocall(__func__);
    int32_t ret = dpdk_module_func.send_pkts_and_recv_pkts_and_gettimeofday(ctxt, ifidx, cur_ts);
    log_exit_ocall(__func__);
    return ret;
}

int32_t ocall_dpdk_send_merged_pkts_and_dpdk_recv_pkts_and_gettimeofday(struct mtcp_thread_context *ctxt, int ifidx, struct timeval* cur_ts) {
    log_enter_ocall(__func__);
    int32_t ret = dpdk_module_func.send_merged_pkts_and_recv_pkts_and_gettimeofday(ctxt, ifidx, cur_ts);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_getrlimit(int resource, struct rlimit *rlim) {
    log_enter_ocall(__func__);
    int ret = getrlimit(resource, rlim);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_setrlimit(int resource, const struct rlimit *rlim) {
    log_enter_ocall(__func__);
    int ret = setrlimit(resource, rlim);
    log_exit_ocall(__func__);
    return ret;
}

struct passwd* ocall_getpwnam(const char *name) {
    log_enter_ocall(__func__);
    struct passwd *ret = getpwnam(name);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_setgroups(size_t size, const gid_t *list) {
    log_enter_ocall(__func__);
    int ret = setgroups(size, list);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_setgid(gid_t gid) {
    log_enter_ocall(__func__);
    int ret = setgid(gid);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_setuid(uid_t uid) {
    log_enter_ocall(__func__);
    int ret = setuid(uid);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_sigignore(int sig) {
    log_enter_ocall(__func__);
    int ret = sigignore(sig);
    log_exit_ocall(__func__);
    return ret;
}

char* ocall_strdup(const char *s) {
    log_enter_ocall(__func__);
    char* ret = strdup(s);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res) {
    log_enter_ocall(__func__);
    int ret = getaddrinfo(node, service, hints, res);
    log_exit_ocall(__func__);
    return ret;
}

struct event_config * ocall_event_config_new(void) {
    log_enter_ocall(__func__);
    struct event_config *ret = event_config_new();
    log_exit_ocall(__func__);
    return ret;
}

int ocall_event_config_set_flag(struct event_config *cfg, int flag) {
    log_enter_ocall(__func__);
    int ret = event_config_set_flag(cfg, flag);
    log_exit_ocall(__func__);
    return ret;
}

struct event_base * ocall_event_base_new_with_config(const struct event_config *cfg) {
    log_enter_ocall(__func__);
    struct event_base *ret = event_base_new_with_config(cfg);
    log_exit_ocall(__func__);
    return ret;
}

void ocall_event_set(struct event *ev, evutil_socket_t fd, short events, void *callback, void *arg) {
    log_enter_ocall(__func__);
    event_set(ev, fd, events, (void (*)(evutil_socket_t, short, void *))callback, arg);
    log_exit_ocall(__func__);
}

int ocall_event_base_set(struct event_base *base, struct event *ev) {
    log_enter_ocall(__func__);
    int ret = event_base_set(base, ev);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_event_add(struct event *ev, const struct timeval *tv) {
    log_enter_ocall(__func__);
    int ret = event_add(ev, tv);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_event_base_loop(struct event_base *base, int flags) {
    log_enter_ocall(__func__);
    int ret = event_base_loop(base, flags);
    log_exit_ocall(__func__);
    return ret;
}

char *ocall_setlocale(int category, const char *locale) {
    log_enter_ocall(__func__);
    char* ret = (char*)setlocale(category, locale);
    log_exit_ocall(__func__);
    return ret;
}

time_t ocall_time(time_t *t) {
    log_enter_ocall(__func__);
    time_t ret = time(t);
    log_exit_ocall(__func__);
    return ret;
}

char *ocall_getcwd(char *buf, size_t size) {
    log_enter_ocall(__func__);
    char* ret = getcwd(buf, size);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_wrapper_stat(const char *pathname, struct stat *statbuf) {
    log_enter_ocall(__func__);
    int ret = stat(pathname, statbuf);
    log_exit_ocall(__func__);
    return ret;
}

int ocall_wrapper_lstat(const char *path, struct stat *sb) {
    log_enter_ocall(__func__);
    int ret = lstat(path, sb);
    log_exit_ocall(__func__);
    return ret;
}

struct tm *ocall_localtime(const time_t *timep) {
	log_enter_ocall(__func__);
	struct tm* ret = localtime(timep);
	log_exit_ocall(__func__);
	return ret;
}

void *ocall_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	log_enter_ocall(__func__);
	void* ret = mmap(addr, length, prot, flags, fd, offset);
	log_exit_ocall(__func__);
	return ret;
}

int ocall_munmap(void *addr, size_t length) {
	log_enter_ocall(__func__);
	int ret = munmap(addr, length);
	log_exit_ocall(__func__);
	return ret;
}

gid_t ocall_getgid(void) {
	log_enter_ocall(__func__);
	gid_t ret = getgid();
	log_exit_ocall(__func__);
	return ret;
}

struct hostent *ocall_gethostbyname(const char *name) {
	log_enter_ocall(__func__);
	struct hostent* ret = gethostbyname(name);
	log_exit_ocall(__func__);
	return ret;
}

void ocall_openlog(const char *ident, int option, int facility) {
	log_enter_ocall(__func__);
	openlog(ident, option, facility);
	log_exit_ocall(__func__);
}

int ocall_fcntl(int fd, int cmd, int arg) {
	log_enter_ocall(__func__);
	int ret = fcntl(fd, cmd, arg);
	log_exit_ocall(__func__);
	return ret;
}

struct tm *ocall_gmtime(const time_t *timep) {
	log_enter_ocall(__func__);
	struct tm* ret = gmtime(timep);
	log_exit_ocall(__func__);
	return ret;
}

off64_t ocall_lseek64(int fd, off64_t offset, int whence) {
	log_enter_ocall(__func__);
	off64_t ret = lseek64(fd, offset, whence);
	log_exit_ocall(__func__);
	return ret;
}

int ocall__getpagesize(void) {
	return getpagesize();
}

