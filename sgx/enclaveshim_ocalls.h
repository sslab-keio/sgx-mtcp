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

#ifndef ENCLAVESHIM_OCALLS_H_
#define ENCLAVESHIM_OCALLS_H_

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <signal.h>
#include <link.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <ifaddrs.h>
#include <getopt.h>
#include <poll.h>
#include <pwd.h>

//#include <rte_mempool.h>
#include <rte_ether.h>
#include <rte_eal.h>
#include <rte_timer.h>

#include "sgx_error.h"       /* sgx_status_t */

#include "mtcp.h"
#include "enclaveshim_config.h"

char *optarg;

// for the signals
typedef void (*sighandler_t)(int);

typedef long int off64_t;

// for memory management
//typedef struct rte_mempool* mem_pool_t;

void print_error_message(sgx_status_t ret);

int my_fprintf(FILE *stream, const char *format, ...);
int my_printf(const char *format, ...);

void __assert_fail(const char *__assertion, const char *__file, unsigned int __line, const char *__function);

void perror(const char *s);

FILE *fopen64(const char *path, const char *mode);
FILE *fopen(const char *path, const char *mode);

char *fgets(char *s, int size, FILE *stream);

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);

int fclose(FILE *fp);

int open(const char *filename, int flags, ...);

ssize_t read(int fd, void *buf, size_t count);

ssize_t write(int fd, const void *buf, size_t count);

static inline ssize_t my_write(int fd, const void *buf, size_t count) {
    return write(fd, buf, count);
}

int close(int fd);

int ioctl1(int fd, unsigned long request, size_t len, void* ptr);

sighandler_t signal(int signum, sighandler_t handler);

long syscall1(long number);

long sysconf(int name);

int clock_gettime(clockid_t clk_id, struct timespec *tp);
int gettimeofday(struct timeval *tv, void *tz);
int usleep(useconds_t usec);

int sched_getcpu(void);

void set_optind(int o);

// mlockall locks this process memory into RAM, preventing the kernel
// from swapping it
int mlockall(int flags);

int sscanf(const char *str, const char *format, ...);

int pipe(int pipefd[2]);

in_addr_t inet_addr(const char *cp);
int socket(int domain, int type, int protocol);
char *inet_ntoa(struct in_addr in);
int getifaddrs(struct ifaddrs **ifap);
void freeifaddrs(struct ifaddrs *ifa);

uid_t getuid(void);
uid_t geteuid(void);
pid_t getpid(void);

void* untrusted_malloc(size_t size);
void* untrusted_calloc(size_t nmemb, size_t size);
void* untrusted_realloc(void* ptr, size_t size);
void untrusted_free(void* ptr);

const unsigned short **__ctype_b_loc(void);

int posix_memalign_on_pagesize(void **memptr, size_t size);

int mlock(const void *addr, size_t len);

int getopt(int argc, char * const *argv, const char *optstring);

int getopt_long(int argc, char * const *argv, const char *optstring,
                const struct option *longopts, int *longindex);

int sched_yield(void);

/***** DPDK ocalls *****/

int rte_thread_set_affinity(cpu_set_t *cpusetp);

// XXX PL: because of these function we need to fix each thread affinity, otherwise the code
// will not find the correct variable
unsigned wrapper_rte_lcore_id(void);
unsigned wrapper_rte_get_master_lcore(void);
unsigned wrapper_rte_socket_id(void);
uint64_t wrapper_rte_rdtsc(void);
int wrapper_rte_lcore_index(int lcore_id);

int ecall_rte_eal_remote_launch_call_callback(void *f, void* arg);

int rte_eal_remote_launch(int (*f)(void *), void *arg, unsigned slave_id);

int rte_eal_wait_lcore(unsigned slave_id);

int rte_eal_init(int argc, char **argv);

uint16_t rte_eth_dev_count_avail(void);

void* rte_calloc_socket(const char *type, size_t num, size_t size, unsigned align, int socket);

void* rte_malloc_socket(const char *type, size_t size, unsigned int align, int socket_arg);

void* rte_zmalloc_socket(const char *type, size_t size, unsigned align, int socket);

struct rte_ring* rte_ring_create(const char *name, unsigned count, int socket_id, unsigned flags);

void rte_free(void *addr);

void rte_eth_macaddr_get(uint16_t port_id, struct ether_addr *mac_addr);

void rte_free(void *addr);

void sgx_dpdk_init_handle(struct mtcp_thread_context *ctxt);

int sgx_dpdk_send_pkts(struct mtcp_thread_context *ctxt, int ifidx);

int sgx_dpdk_send_merged_pkts(struct mtcp_thread_context *ctxt, int ifidx);

void sgx_free_pkts(struct rte_mbuf **mtable, unsigned len);

int32_t sgx_dpdk_recv_pkts(struct mtcp_thread_context *ctxt, int ifidx);

int32_t sgx_dpdk_recv_pkts_and_gettimeofday(struct mtcp_thread_context *ctxt, int ifidx, struct timeval* cur_ts);

int32_t sgx_dpdk_send_pkts_and_dpdk_recv_pkts_and_gettimeofday(struct mtcp_thread_context *ctxt, int ifidx, struct timeval* cur_ts);

int32_t sgx_dpdk_send_merged_pkts_and_dpdk_recv_pkts_and_gettimeofday(struct mtcp_thread_context *ctxt, int ifidx, struct timeval* cur_ts);

void sgx_dpdk_destroy_handle(struct mtcp_thread_context *ctxt);

void sgx_check_all_ports_link_status(uint8_t port_num, uint32_t port_mask);

void sgx_dpdk_load_module(struct mtcp_config, int num_devices_attached, int devices_attached[MAX_DEVICES]);

void sgx_get_dev_info(int nif, char** driver_name, uint64_t* tx_offload_capa, uint64_t* rx_offload_capa);

enum rte_proc_type_t eal_proc_type_detect(void);

void set_lcore_config(int master, int ret, enum rte_lcore_state_t state);

char *strsignal(int sig);

int getrusage(int who, struct rusage *usage);

int raise(int sig);

int listen(int s, int backlog);

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

ssize_t wrapper_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

int setuid(uid_t uid);

gid_t getgid(void);

mode_t umask(mode_t mask);

int rename(const char *oldpath, const char *newpath);

time_t time(time_t *t);

int kill(pid_t pid, int sig);

int unlink(const char *pathname);

int fcntl(int fd, int cmd, ...);

int access(const char *pathname, int mode);

int sigignore(int sig);

pid_t setsid(void);

void setbuf(FILE *stream, char *buf);

int wrapper_stat(const char *pathname, struct stat *statbuf);

int wrapper_lstat(const char *path, struct stat *sb);

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res);

void freeaddrinfo(struct addrinfo *res);

const char *gai_strerror(int errcode);

int dup(int oldfd);

int dup2(int oldfd, int newfd);

char *strdup(const char *s);

int getsubopt(char **optionp, char * const *tokens, char **valuep);

struct passwd *getpwnam(const char *name);

int getgroups(int size, gid_t list[]);

int setgroups(size_t size, const gid_t *list);

int madvise(void * start , size_t length , int advice);

int chdir(const char *path);

pid_t fork(void);

int posix_memalign(void **memptr, size_t alignment, size_t size);

int wrapper_poll(struct pollfd *fds, nfds_t nfds, int timeout);

int wrapper_getrlimit(int resource, struct rlimit *rlim);

int wrapper_setrlimit(int resource, const struct rlimit *rlim);

// libevent
#include <event.h>

int event_add (struct event *ev, const struct timeval *timeout);
int event_del(struct event *ev);
void event_set (struct event *ev, int fd, short event, void(*cb)(int, short, void *), void *arg);
int event_base_set(struct event_base *base, struct event *ev);
const char * event_get_version(void);
struct event_config * event_config_new(void);
int event_config_set_flag(struct event_config *cfg, int flag);
struct event_base * event_base_new_with_config(const struct event_config *cfg);
void event_config_free(struct event_config *cfg);
int event_base_loop(struct event_base *base, int flags);
void event_base_free(struct event_base *base);

// lighttpd

#include <sys/epoll.h>

int chroot(const char *path);
int closedir(DIR *dirp);
void closelog(void);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int epoll_create(int size);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
int execl(const char *path, const char *arg, ... /* (char  *) NULL */);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
char *getcwd(char *buf, size_t size);
gid_t getegid(void);
struct group *getgrnam(const char *name);
struct hostent *gethostbyname(const char *name);
struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type);
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
struct tm *gmtime(const time_t *timep);
int inet_aton(const char *cp, struct in_addr *inp);
int initgroups(const char *user, gid_t group);
struct tm *localtime(const time_t *timep);
struct tm *localtime_r(const time_t *timep, struct tm *result);
time_t mktime(struct tm *tm);
off64_t lseek64(int fd, off64_t offset, int whence);
void *mmap(void *addr, size_t length, int prot, int flags, int fod, off_t offset);
void *wrapper_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void *addr, size_t length);
DIR *opendir(const char *name);
void openlog(const char *ident, int option, int facility);
long pathconf(const char *path, int name);
int poll(struct pollfd *fds, nfds_t nfds, int timeout);
int prctl(int option, ...);
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
char *setlocale(int category, const char *locale);
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
int sigemptyset(sigset_t *set);
unsigned int sleep(unsigned int seconds);
char *strptime(const char *s, const char *format, struct tm *tm);
void tzset (void);
pid_t wait(int *wstatus);
pid_t waitpid(pid_t pid, int *wstatus, int options);
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
int open64(const char *filename, int flags, ...);
struct dirent *wrapper_readdir(DIR *dirp);
int wrapper_mkstemp(char *template);
ssize_t wrapper_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
long int __fdelt_chk (long int __d);
int wrapper_putc(int c, FILE *stream);
int wrapper_syslog(int priority, const char *format, ...);
int __getpagesize(void);
#endif
