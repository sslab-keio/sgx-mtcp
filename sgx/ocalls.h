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

#ifndef OCALLS_H_
#define OCALLS_H_

#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/resource.h>
#include <getopt.h>
#include <pwd.h>
#include <event.h>
#include <sys/stat.h>

#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

#include "mtcp.h"

void ocall_print_string(const char* str);
void ocall_println_string(const char* str);

void ocall_exit(int s);

void* ocall_fopen(const char *path, const char *mode);
char* ocall_fgets(char *s, int size, void *stream);
size_t ocall_fwrite(const void *ptr, size_t size, size_t nmemb, void *stream);
size_t ocall_fwrite_copy(const void *ptr, size_t size, size_t nmemb, void *stream);
int ocall_fclose(void* fp);
int ocall_fflush(void* stream);

int ocall_open(const char *filename, int flags, mode_t mode);
int ocall_open64(const char *filename, int flags, mode_t mode);
ssize_t ocall_read(int fd, void *buf, size_t count);
ssize_t ocall_write(int fd, const void *buf, size_t count);
int ocall_close(int fd);
int ocall_pipe(int pipefd[2]);

void* ocall_malloc(size_t size);
void* ocall_realloc(void* ptr, size_t size);
void* ocall_calloc(size_t nmemb, size_t size);
void ocall_free(void* ptr);

int ocall_ioctl1(int fd, unsigned long request, size_t len, void* ptr);
void* ocall_signal(int signum, void* handler);
long ocall_syscall1(long number);
long ocall_sysconf(int name);
void ocall_perror(const char *s);

int ocall_clock_gettime(clockid_t clk_id, struct timespec *tp);
int ocall_gettimeofday(struct timeval *tv, struct timezone *tz);
int ocall_usleep(useconds_t usec);

int ocall_sched_getcpu(void);
void ocall_set_optind(int o);
int ocall_mlockall(int flags);

in_addr_t ocall_inet_addr(const char *cp);
int ocall_socket(int domain, int type, int protocol);
char *ocall_inet_ntoa(struct in_addr in);
int ocall_getifaddrs(struct ifaddrs **ifap);
void ocall_freeifaddrs(struct ifaddrs *ifa);

uid_t ocall_getuid(void);
uid_t ocall_geteuid(void);
pid_t ocall_getpid(void);

int ocall_posix_memalign_on_pagesize(void **memptr, size_t size);
int ocall_mlock(const void *addr, size_t len);

int ocall_getopt(int argc, char **argv, const char *optstring);
int ocall_getopt_long(int argc, char **argv, const char *optstring,
                const struct option *longopts, int *longindex);
char* ocall_getoptarg();

int ocall_sched_yield(void);

/* thread ocalls */
int ocall_pthread_create(thread_t *thread, const thread_attr_t *attr, void *start_routine, void *arg);
void ocall_pthread_exit(void *ret);
int ocall_pthread_join(thread_t th, void **thread_return);
int ocall_pthread_setspecific(thread_key_t key, const void *ptr);
void* ocall_pthread_getspecific(thread_key_t key);
int ocall_pthread_key_create(thread_key_t *key, void *destr_function);

int ocall_sem_init(sem_t *sem, int pshared, unsigned int value);
int ocall_sem_destroy(sem_t *sem);
int ocall_sem_wait(sem_t *sem);
int ocall_sem_post(sem_t *sem);

/* DPDK ocalls */
void ocall_set_lcore_config(int master, int ret, enum rte_lcore_state_t state);
int ocall_rte_eal_init(int argc, char **argv);
int ocall_rte_eal_remote_launch(void* f, void *arg, unsigned slave_id);
uint16_t ocall_rte_eth_dev_count_avail(void);
void* ocall_rte_calloc_socket(const char *type, size_t num, size_t size, unsigned align, int socket);
void* ocall_rte_malloc_socket(const char *type, size_t size, unsigned int align, int socket_arg);
void* ocall_rte_ring_create(const char *name, unsigned count, int socket_id, unsigned flags);
uint64_t ocall_rte_rdtsc(void);
void ocall_rte_free(void *addr);
void ocall_rte_eth_macaddr_get(uint16_t port_id, struct ether_addr *mac_addr);
enum rte_proc_type_t ocall_eal_proc_type_detect(void);
int ocall_rte_thread_set_affinity(cpu_set_t *cpusetp);
unsigned ocall_rte_lcore_id(void);
unsigned ocall_rte_get_master_lcore(void);
unsigned ocall_rte_socket_id(void);
int ocall_rte_lcore_index(int lcore_id);
void ocall_dpdk_load_module(struct mtcp_config conf, int _num_devices_attached, int* _devices_attached);
void ocall_dpdk_init_handle(struct mtcp_thread_context *ctxt);
int ocall_dpdk_send_pkts(struct mtcp_thread_context *ctxt, int ifidx);
int ocall_dpdk_send_merged_pkts(struct mtcp_thread_context *ctxt, int ifidx);
int32_t ocall_dpdk_recv_pkts(struct mtcp_thread_context *ctxt, int ifidx);
void ocall_dpdk_get_dev_info(int nif, char** driver_name, uint64_t* tx_offload_capa, uint64_t* rx_offload_capa);
int32_t ocall_dpdk_recv_pkts_and_gettimeofday(struct mtcp_thread_context *ctxt, int ifidx, struct timeval* cur_ts);
int32_t ocall_dpdk_send_pkts_and_dpdk_recv_pkts_and_gettimeofday(struct mtcp_thread_context *ctxt, int ifidx, struct timeval* cur_ts);
int32_t ocall_dpdk_send_merged_pkts_and_dpdk_recv_pkts_and_gettimeofday(struct mtcp_thread_context *ctxt, int ifidx, struct timeval* cur_ts);

int ocall_getrlimit(int resource, struct rlimit *rlim);
int ocall_setrlimit(int resource, const struct rlimit *rlim);
struct passwd* ocall_getpwnam(const char *name);
int ocall_setgroups(size_t size, const gid_t *list);
int ocall_setgid(gid_t gid);
int ocall_setuid(uid_t uid);
int ocall_sigignore(int sig);
char* ocall_strdup(const char *s);
int ocall_getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res);

struct event_config * ocall_event_config_new(void);
int ocall_event_config_set_flag(struct event_config *cfg, int flag);
struct event_base * ocall_event_base_new_with_config(const struct event_config *cfg);
void ocall_event_set(struct event *ev, evutil_socket_t fd, short events, void *callback, void *arg);
int ocall_event_base_set(struct event_base *base, struct event *ev);
int ocall_event_add(struct event *ev, const struct timeval *tv);
int ocall_event_base_loop(struct event_base *base, int flags);

char *ocall_setlocale(int category, const char *locale);
time_t ocall_time(time_t *t);
char *ocall_getcwd(char *buf, size_t size);
int ocall_wrapper_stat(const char *pathname, struct stat *statbuf);
int ocall_wrapper_lstat(const char *path, struct stat *sb);
struct tm *ocall_localtime(const time_t *timep);
void *ocall_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int ocall_munmap(void *addr, size_t length);
gid_t ocall_getgid(void);
struct hostent *ocall_gethostbyname(const char *name);
void ocall_openlog(const char *ident, int option, int facility);
int ocall_fcntl(int fd, int cmd, int arg);
struct tm *ocall_gmtime(const time_t *timep);
off64_t ocall_lseek64(int fd, off64_t offset, int whence);
int ocall__getpagesize(void);
#endif
