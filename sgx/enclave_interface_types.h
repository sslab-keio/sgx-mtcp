//
// Created by pl on 19/05/07.
//

#ifndef SGX_MTCP_ENCLAVE_INTERFACE_TYPES_H
#define SGX_MTCP_ENCLAVE_INTERFACE_TYPES_H

typedef unsigned int mode_t;

typedef unsigned int uid_t;

typedef unsigned int gid_t;

typedef int pid_t;

typedef unsigned int socklen_t;

typedef long int ssize_t;

#ifdef SGX_DEFINE_STRUCTURES

#include <sgx_thread.h>

typedef long int __time_t;
typedef long int time_t;
typedef unsigned int __useconds_t;
typedef __useconds_t useconds_t;
typedef long int __suseconds_t;
typedef int clockid_t;

struct timezone
{
    int tz_minuteswest;
    int tz_dsttime;
};

struct timeval
{
	__time_t tv_sec;
	__suseconds_t tv_usec;
};

typedef long int __syscall_slong_t;
struct timespec
  {
    __time_t tv_sec;
    __syscall_slong_t tv_nsec;
};

/* Structure for scatter/gather I/O.  */
struct iovec
{
  void *iov_base;	/* Pointer to data.  */
  size_t iov_len;	/* Length of data.  */
};

typedef uint32_t in_addr_t;
struct in_addr
{
    in_addr_t s_addr;
};

/* The `getifaddrs' function generates a linked list of these structures.
   Each element of the list describes one network interface.  */
struct ifaddrs
{
    struct ifaddrs *ifa_next;	/* Pointer to the next structure.  */

    char *ifa_name;		/* Name of this network interface.  */
    unsigned int ifa_flags;	/* Flags as from SIOCGIFFLAGS ioctl.  */

    struct sockaddr *ifa_addr;	/* Network address of this interface.  */
    struct sockaddr *ifa_netmask; /* Netmask of this interface.  */
    union
    {
        /* At most one of the following two is valid.  If the IFF_BROADCAST
           bit is set in `ifa_flags', then `ifa_broadaddr' is valid.  If the
           IFF_POINTOPOINT bit is set, then `ifa_dstaddr' is valid.
           It is never the case that both these bits are set at once.  */
        struct sockaddr *ifu_broadaddr; /* Broadcast address of this interface. */
        struct sockaddr *ifu_dstaddr; /* Point-to-point destination address.  */
    } ifa_ifu;
    /* These very same macros are defined by <net/if.h> for `struct ifaddr'.
       So if they are defined already, the existing definitions will be fine.  */
# ifndef ifa_broadaddr
#  define ifa_broadaddr	ifa_ifu.ifu_broadaddr
# endif
# ifndef ifa_dstaddr
#  define ifa_dstaddr	ifa_ifu.ifu_dstaddr
# endif

    void *ifa_data;		/* Address-specific data (may be unused).  */
};

typedef unsigned long int rlim_t;

struct rlimit
{
  /* The current (soft) limit.  */
  rlim_t rlim_cur;
  /* The hard limit.  */
  rlim_t rlim_max;
};

struct option
{
  const char *name;
  /* has_arg can't be an enum because some compilers complain about
     type mismatches in all the code that assumes it is an int.  */
  int has_arg;
  int *flag;
  int val;
};

/* The passwd structure.  */
struct passwd
{
  char *pw_name;		/* Username.  */
  char *pw_passwd;		/* Password.  */
  uid_t pw_uid;		/* User ID.  */
  gid_t pw_gid;		/* Group ID.  */
  char *pw_gecos;		/* Real name.  */
  char *pw_dir;			/* Home directory.  */
  char *pw_shell;		/* Shell program.  */
};

struct mtcp_context
{
    int cpu;
};
typedef struct mtcp_context *mctx_t;

struct mtcp_conf
{
	int num_cores;
	int max_concurrency;

	int max_num_buffers;
	int rcvbuf_size;
	int sndbuf_size;

	int tcp_timewait;
	int tcp_timeout;
};

typedef union mtcp_epoll_data
{
    void *ptr;
    int sockid;
    uint32_t u32;
    uint64_t u64;
} mtcp_epoll_data_t;

struct mtcp_epoll_event
{
    uint32_t events;
    mtcp_epoll_data_t data;
};

#define ETHER_ADDR_LEN  6 /**< Length of Ethernet address. */
/**
 * Ethernet address:
 * A universally administered address is uniquely assigned to a device by its
 * manufacturer. The first three octets (in transmission order) contain the
 * Organizationally Unique Identifier (OUI). The following three (MAC-48 and
 * EUI-48) octets are assigned by that organization with the only constraint
 * of uniqueness.
 * A locally administered address is assigned to a device by a network
 * administrator and does not contain OUIs.
 * See http://standards.ieee.org/regauth/groupmac/tutorial.html
 */
struct ether_addr {
    uint8_t addr_bytes[ETHER_ADDR_LEN]; /**< Addr bytes in tx order */
} __attribute__((__packed__));

/**
 * The type of process in a linuxapp, multi-process setup
 */
enum rte_proc_type_t {
	RTE_PROC_AUTO = -1,   /* allow auto-detection of primary/secondary */
	RTE_PROC_PRIMARY = 0, /* set to zero, so primary is the default */
	RTE_PROC_SECONDARY,
	RTE_PROC_INVALID
};

/* Thread identifiers.  The structure of the attribute type is not
   exposed on purpose.  */
typedef unsigned long int pthread_t;
typedef pthread_t thread_t;
typedef void* thread_attr_t;
typedef unsigned int thread_key_t;

/* Size definition for CPU sets.  */
#define __CPU_SETSIZE	1024
#define __NCPUBITS	(8 * sizeof (unsigned long int))

/* Data structure to describe CPU mask.  */
typedef struct
{
    unsigned long int __bits[__CPU_SETSIZE / __NCPUBITS];
} cpu_set_t;

typedef	cpu_set_t rte_cpuset_t;

/**
 * Definition of a remote launch function.
 */
typedef int (lcore_function_t)(void *);

/**
 * State of an lcore.
 */
enum rte_lcore_state_t {
    WAIT,       /**< waiting a new command */
    RUNNING,    /**< executing command */
    FINISHED,   /**< command executed */
};

/** C extension macro for environments lacking C11 features. */
#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
#define RTE_STD_C11 __extension__
#else
#define RTE_STD_C11
#endif

typedef uint64_t phys_addr_t; /**< Physical address. */

/**
 * IO virtual address type.
 * When the physical addressing mode (IOVA as PA) is in use,
 * the translation from an IO virtual address (IOVA) to a physical address
 * is a direct mapping, i.e. the same value.
 * Otherwise, in virtual mode (IOVA as VA), an IOMMU may do the translation.
 */
typedef uint64_t rte_iova_t;

#define	STAILQ_ENTRY(type)						\
struct {								\
	struct type *stqe_next;	/* next element */			\
}

/*
 * Singly-linked Tail queue declarations.
 */
#define	STAILQ_HEAD(name, type)					\
struct name {								\
	struct type *stqh_first;	/* first element */			\
	struct type **stqh_last;	/* addr of last next element */		\
}

/**
 * A list of object headers type
 */
STAILQ_HEAD(rte_mempool_objhdr_list, rte_mempool_objhdr);

/**
 * A list of memory where objects are stored
 */
STAILQ_HEAD(rte_mempool_memhdr_list, rte_mempool_memhdr);

/**
 * Mempool object header structure
 *
 * Each object stored in mempools are prefixed by this header structure,
 * it allows to retrieve the mempool pointer from the object and to
 * iterate on all objects attached to a mempool. When debug is enabled,
 * a cookie is also added in this structure preventing corruptions and
 * double-frees.
 */
struct rte_mempool_objhdr {
	STAILQ_ENTRY(rte_mempool_objhdr) next; /**< Next in list. */
	struct rte_mempool *mp;          /**< The mempool owning the object. */
	RTE_STD_C11
	union {
		rte_iova_t iova;         /**< IO address of the object. */
		phys_addr_t physaddr;    /**< deprecated - Physical address of the object. */
	};
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
	uint64_t cookie;                 /**< Debug cookie. */
#endif
};

/**
 * A structure describing a memzone, which is a contiguous portion of
 * physical memory identified by a name.
 */
struct rte_memzone {

#define RTE_MEMZONE_NAMESIZE 32       /**< Maximum length of memory zone name.*/
	char name[RTE_MEMZONE_NAMESIZE];  /**< Name of the memory zone. */

	RTE_STD_C11
	union {
		phys_addr_t phys_addr;        /**< deprecated - Start physical address. */
		rte_iova_t iova;              /**< Start IO address. */
	};
	RTE_STD_C11
	union {
		void *addr;                   /**< Start virtual address. */
		uint64_t addr_64;             /**< Makes sure addr is always 64-bits */
	};
	size_t len;                       /**< Length of the memzone. */

	uint64_t hugepage_sz;             /**< The page size of underlying memory */

	int32_t socket_id;                /**< NUMA socket ID. */

	uint32_t flags;                   /**< Characteristics of this memzone. */
} __attribute__((__packed__));

/**
 * The RTE mempool structure.
 */
struct rte_mempool {
	/*
	 * Note: this field kept the RTE_MEMZONE_NAMESIZE size due to ABI
	 * compatibility requirements, it could be changed to
	 * RTE_MEMPOOL_NAMESIZE next time the ABI changes
	 */
	char name[RTE_MEMZONE_NAMESIZE]; /**< Name of mempool. */
	RTE_STD_C11
	union {
		void *pool_data;         /**< Ring or pool to store objects. */
		uint64_t pool_id;        /**< External mempool identifier. */
	};
	void *pool_config;               /**< optional args for ops alloc. */
	const struct rte_memzone *mz;    /**< Memzone where pool is alloc'd. */
	unsigned int flags;              /**< Flags of the mempool. */
	int socket_id;                   /**< Socket id passed at create. */
	uint32_t size;                   /**< Max size of the mempool. */
	uint32_t cache_size;
	/**< Size of per-lcore default local cache. */

	uint32_t elt_size;               /**< Size of an element. */
	uint32_t header_size;            /**< Size of header (before elt). */
	uint32_t trailer_size;           /**< Size of trailer (after elt). */

	unsigned private_data_size;      /**< Size of private data. */
	/**
	 * Index into rte_mempool_ops_table array of mempool ops
	 * structs, which contain callback function pointers.
	 * We're using an index here rather than pointers to the callbacks
	 * to facilitate any secondary processes that may want to use
	 * this mempool.
	 */
	int32_t ops_index;

	struct rte_mempool_cache *local_cache; /**< Per-lcore local cache */

	uint32_t populated_size;         /**< Number of populated objects. */
	struct rte_mempool_objhdr_list elt_list; /**< List of objects in pool */
	uint32_t nb_mem_chunks;          /**< Number of memory chunks */
	struct rte_mempool_memhdr_list mem_list; /**< List of memory chunks */

#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
	/** Per-lcore statistics. */
	struct rte_mempool_debug_stats stats[RTE_MAX_LCORE];
#endif
}  __rte_cache_aligned;

// for memory management
typedef struct rte_mempool* mem_pool_t;

/**
 * Structure storing internal configuration (per-lcore)
 */
struct lcore_config {
    unsigned detected;         /**< true if lcore was detected */
    pthread_t thread_id;       /**< pthread identifier */
    int pipe_master2slave[2];  /**< communication pipe with master */
    int pipe_slave2master[2];  /**< communication pipe with master */
    lcore_function_t * volatile f;         /**< function to call */
    void * volatile arg;       /**< argument of function */
    volatile int ret;          /**< return value of function */
    volatile enum rte_lcore_state_t state; /**< lcore state */
    unsigned socket_id;        /**< physical socket id for this lcore */
    unsigned core_id;          /**< core number on socket for this lcore */
    int core_index;            /**< relative index, starting from 0 */
    rte_cpuset_t cpuset;       /**< cpu set which the lcore affinity to */
    uint8_t core_role;         /**< role of core eg: OFF, RTE, SERVICE */
};

# define __SIZEOF_SEM_T	32

typedef union
{
    char __size[__SIZEOF_SEM_T];
    long int __align;
} sem_t;

#define MAX_DEVICES		128

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

struct eth_table
{
	char dev_name[128];
	int ifindex;
	int stat_print;
	unsigned char haddr[ETH_ALEN];
	uint32_t netmask;
//	unsigned char dst_haddr[ETH_ALEN];
	uint32_t ip_addr;
};
/*----------------------------------------------------------------------------*/
struct route_table
{
	uint32_t daddr;
	uint32_t mask;
	uint32_t masked;
	int prefix;
	int nif;
};
/*----------------------------------------------------------------------------*/
struct arp_entry
{
	uint32_t ip;
	int8_t prefix;
	uint32_t ip_mask;
	uint32_t ip_masked;
	unsigned char haddr[ETH_ALEN];
};
/*----------------------------------------------------------------------------*/
struct arp_table
{
	struct arp_entry *entry;
	struct arp_entry *gateway;
	int entries;
};

struct mtcp_config
{
	/* network interface config */
	struct eth_table *eths;
	int *nif_to_eidx; // mapping physic port indexes to that of the configured port-list
	int eths_num;

	/* route config */
	struct route_table *rtable;		// routing table
	struct route_table *gateway;
	int routes;						// # of entries

	/* arp config */
	struct arp_table arp;

	int num_cores;
	int num_mem_ch;
	int max_concurrency;
	size_t _cpumask;

	int max_num_buffers;
	int rcvbuf_size;
	int sndbuf_size;

	int tcp_timewait;
	int tcp_timeout;

	/* adding multi-process support */
	uint8_t multi_process;
	uint8_t multi_process_is_master;
};

struct mtcp_thread_context
{
	int cpu;
#if COMPILE_WITH_SGX && ENABLE_UCTX
	struct lthread * thread;
#else
	sgx_thread_t thread;
#endif
	uint8_t done:1,
			exit:1,
			interrupt:1;

	struct mtcp_manager* mtcp_manager;

	void *io_private_context;
	sgx_thread_mutex_t smap_lock;
	sgx_thread_mutex_t flow_pool_lock;
	sgx_thread_mutex_t socket_pool_lock;
};

typedef volatile uint32_t sgx_spinlock_t;

/* Structure to contain information about address of a service provider.  */
struct addrinfo
{
  int ai_flags;			/* Input flags.  */
  int ai_family;		/* Protocol family for socket.  */
  int ai_socktype;		/* Socket type.  */
  int ai_protocol;		/* Protocol for socket.  */
  socklen_t ai_addrlen;		/* Length of socket address.  */
  struct sockaddr *ai_addr;	/* Socket address for socket.  */
  char *ai_canonname;		/* Canonical name for service location.  */
  struct addrinfo *ai_next;	/* Pointer to next in list.  */
};

// libevent
#define TAILQ_HEAD(name, type)						\
struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type **tqh_last;	/* addr of last next element */		\
}

/* Fix so that people don't have to run with <sys/queue.h> */
#ifndef TAILQ_ENTRY
#define EVENT_DEFINED_TQENTRY_
#define TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
}
#endif /* !TAILQ_ENTRY */

#define LIST_HEAD(name, type)						\
struct name {								\
	struct type *lh_first;	/* first element */			\
}

#define LIST_ENTRY(type)						\
struct {								\
	struct type *le_next;	/* next element */			\
	struct type **le_prev;	/* address of previous next element */	\
}

#define evutil_socket_t int
#define ev_uint8_t uint8_t
#define ev_uint32_t uint32_t

/**
   A flag used to describe which features an event_base (must) provide.

   Because of OS limitations, not every Libevent backend supports every
   possible feature.  You can use this type with
   event_config_require_features() to tell Libevent to only proceed if your
   event_base implements a given feature, and you can receive this type from
   event_base_get_features() to see which features are available.
*/
enum event_method_feature {
    /** Require an event method that allows edge-triggered events with EV_ET. */
    EV_FEATURE_ET = 0x01,
    /** Require an event method where having one event triggered among
     * many is [approximately] an O(1) operation. This excludes (for
     * example) select and poll, which are approximately O(N) for N
     * equal to the total number of possible events. */
    EV_FEATURE_O1 = 0x02,
    /** Require an event method that allows file descriptors as well as
     * sockets. */
    EV_FEATURE_FDS = 0x04,
    /** Require an event method that allows you to use EV_CLOSED to detect
     * connection close without the necessity of reading all the pending data.
     *
     * Methods that do support EV_CLOSED may not be able to provide support on
     * all kernel versions.
     **/
    EV_FEATURE_EARLY_CLOSE = 0x08
};

/**
   A flag passed to event_config_set_flag().

    These flags change the behavior of an allocated event_base.

    @see event_config_set_flag(), event_base_new_with_config(),
       event_method_feature
 */
enum event_base_config_flag {
	/** Do not allocate a lock for the event base, even if we have
	    locking set up.

	    Setting this option will make it unsafe and nonfunctional to call
	    functions on the base concurrently from multiple threads.
	*/
	EVENT_BASE_FLAG_NOLOCK = 0x01,
	/** Do not check the EVENT_* environment variables when configuring
	    an event_base  */
	EVENT_BASE_FLAG_IGNORE_ENV = 0x02,
	/** Windows only: enable the IOCP dispatcher at startup

	    If this flag is set then bufferevent_socket_new() and
	    evconn_listener_new() will use IOCP-backed implementations
	    instead of the usual select-based one on Windows.
	 */
	EVENT_BASE_FLAG_STARTUP_IOCP = 0x04,
	/** Instead of checking the current time every time the event loop is
	    ready to run timeout callbacks, check after each timeout callback.
	 */
	EVENT_BASE_FLAG_NO_CACHE_TIME = 0x08,

	/** If we are using the epoll backend, this flag says that it is
	    safe to use Libevent's internal change-list code to batch up
	    adds and deletes in order to try to do as few syscalls as
	    possible.  Setting this flag can make your code run faster, but
	    it may trigger a Linux bug: it is not safe to use this flag
	    if you have any fds cloned by dup() or its variants.  Doing so
	    will produce strange and hard-to-diagnose bugs.

	    This flag can also be activated by setting the
	    EVENT_EPOLL_USE_CHANGELIST environment variable.

	    This flag has no effect if you wind up using a backend other than
	    epoll.
	 */
	EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST = 0x10,

	/** Ordinarily, Libevent implements its time and timeout code using
	    the fastest monotonic timer that we have.  If this flag is set,
	    however, we use less efficient more precise timer, assuming one is
	    present.
	 */
	EVENT_BASE_FLAG_PRECISE_TIMER = 0x20
};

typedef struct min_heap
{
	struct event** p;
	unsigned n, a;
} min_heap_t;

struct evutil_monotonic_timer {

#ifdef HAVE_MACH_MONOTONIC
	struct mach_timebase_info mach_timebase_units;
#endif

#ifdef HAVE_POSIX_MONOTONIC
	int monotonic_clock;
#endif

#ifdef HAVE_WIN32_MONOTONIC
	ev_GetTickCount_func GetTickCount64_fn;
	ev_GetTickCount_func GetTickCount_fn;
	ev_uint64_t last_tick_count;
	ev_uint64_t adjust_tick_count;

	ev_uint64_t first_tick;
	ev_uint64_t first_counter;
	double usec_per_count;
	int use_performance_counter;
#endif

	struct timeval adjust_monotonic_clock;
	struct timeval last_time;
};

/* Structure to hold the state of our weak random number generator.
 */
struct evutil_weakrand_state {
	ev_uint32_t seed;
};

#define event_io_map event_signal_map
/* Used to map signal numbers to a list of events.  If EVMAP_USE_HT is not
   defined, this structure is also used as event_io_map, which maps fds to a
   list of events.
*/
struct event_signal_map {
	/* An array of evmap_io * or of evmap_signal *; empty entries are
	 * set to NULL. */
	void **entries;
	/* The number of entries available in entries */
	int nentries;
};

TAILQ_HEAD(evcallback_list, event_callback);

struct event;
struct event_callback {
	TAILQ_ENTRY(event_callback) evcb_active_next;
	short evcb_flags;
	ev_uint8_t evcb_pri;	/* smaller numbers are higher priority */
	ev_uint8_t evcb_closure;
	/* allows us to adopt for different types of events */
        union {
		void (*evcb_callback)(evutil_socket_t, short, void *);
		void (*evcb_selfcb)(struct event_callback *, void *);
		void (*evcb_evfinalize)(struct event *, void *);
		void (*evcb_cbfinalize)(struct event_callback *, void *);
	} evcb_cb_union;
	void *evcb_arg;
};

struct event {
	struct event_callback ev_evcallback;

	/* for managing timeouts */
	union {
		TAILQ_ENTRY(event) ev_next_with_common_timeout;
		int min_heap_idx;
	} ev_timeout_pos;
	evutil_socket_t ev_fd;

	struct event_base *ev_base;

	union {
		/* used for io events */
		struct {
			LIST_ENTRY (event) ev_io_next;
			struct timeval ev_timeout;
		} ev_io;

		/* used by signal events */
		struct {
			LIST_ENTRY (event) ev_signal_next;
			short ev_ncalls;
			/* Allows deletes in callback */
			short *ev_pncalls;
		} ev_signal;
	} ev_;

	short ev_events;
	short ev_res;		/* result passed to event callback */
	struct timeval ev_timeout;
};

typedef void (*ev_sighandler_t)(int);

/* Data structure for the default signal-handling implementation in signal.c
 */
struct evsig_info {
	/* Event watching ev_signal_pair[1] */
	struct event ev_signal;
	/* Socketpair used to send notifications from the signal handler */
	evutil_socket_t ev_signal_pair[2];
	/* True iff we've added the ev_signal event yet. */
	int ev_signal_added;
	/* Count of the number of signals we're currently watching. */
	int ev_n_signals_added;

	/* Array of previous signal handler objects before Libevent started
	 * messing with them.  Used to restore old signal handlers. */
#ifdef EVENT__HAVE_SIGACTION
	struct sigaction **sh_old;
#else
	ev_sighandler_t **sh_old;
#endif
	/* Size of sh_old. */
	int sh_old_max;
};

/** Internal structure: describes the configuration we want for an event_base
 * that we're about to allocate. */
struct event_config {
	TAILQ_HEAD(event_configq, event_config_entry) entries;

	int n_cpus_hint;
	struct timeval max_dispatch_interval;
	int max_dispatch_callbacks;
	int limit_callbacks_after_prio;
	enum event_method_feature require_features;
	enum event_base_config_flag flags;
};

/** Represents a */
struct event_change {
	/** The fd or signal whose events are to be changed */
	evutil_socket_t fd;
	/* The events that were enabled on the fd before any of these changes
	   were made.  May include EV_READ or EV_WRITE. */
	short old_events;

	/* The changes that we want to make in reading and writing on this fd.
	 * If this is a signal, then read_change has EV_CHANGE_SIGNAL set,
	 * and write_change is unused. */
	ev_uint8_t read_change;
	ev_uint8_t write_change;
	ev_uint8_t close_change;
};

/* List of 'changes' since the last call to eventop.dispatch.  Only maintained
 * if the backend is using changesets. */
struct event_changelist {
	struct event_change *changes;
	int n_changes;
	int changes_size;
};

struct event_base {
	/** Function pointers and other data to describe this event_base's
	 * backend. */
	const struct eventop *evsel;
	/** Pointer to backend-specific data. */
	void *evbase;

	/** List of changes to tell backend about at next dispatch.  Only used
	 * by the O(1) backends. */
	struct event_changelist changelist;

	/** Function pointers used to describe the backend that this event_base
	 * uses for signals */
	const struct eventop *evsigsel;
	/** Data to implement the common signal handelr code. */
	struct evsig_info sig;

	/** Number of virtual events */
	int virtual_event_count;
	/** Maximum number of virtual events active */
	int virtual_event_count_max;
	/** Number of total events added to this event_base */
	int event_count;
	/** Maximum number of total events added to this event_base */
	int event_count_max;
	/** Number of total events active in this event_base */
	int event_count_active;
	/** Maximum number of total events active in this event_base */
	int event_count_active_max;

	/** Set if we should terminate the loop once we're done processing
	 * events. */
	int event_gotterm;
	/** Set if we should terminate the loop immediately */
	int event_break;
	/** Set if we should start a new instance of the loop immediately. */
	int event_continue;

	/** The currently running priority of events */
	int event_running_priority;

	/** Set if we're running the event_base_loop function, to prevent
	 * reentrant invocation. */
	int running_loop;

	/** Set to the number of deferred_cbs we've made 'active' in the
	 * loop.  This is a hack to prevent starvation; it would be smarter
	 * to just use event_config_set_max_dispatch_interval's max_callbacks
	 * feature */
	int n_deferreds_queued;

	/* Active event management. */
	/** An array of nactivequeues queues for active event_callbacks (ones
	 * that have triggered, and whose callbacks need to be called).  Low
	 * priority numbers are more important, and stall higher ones.
	 */
	struct evcallback_list *activequeues;
	/** The length of the activequeues array */
	int nactivequeues;
	/** A list of event_callbacks that should become active the next time
	 * we process events, but not this time. */
	struct evcallback_list active_later_queue;

	/* common timeout logic */

	/** An array of common_timeout_list* for all of the common timeout
	 * values we know. */
	struct common_timeout_list **common_timeout_queues;
	/** The number of entries used in common_timeout_queues */
	int n_common_timeouts;
	/** The total size of common_timeout_queues. */
	int n_common_timeouts_allocated;

	/** Mapping from file descriptors to enabled (added) events */
	struct event_io_map io;

	/** Mapping from signal numbers to enabled (added) events. */
	struct event_signal_map sigmap;

	/** Priority queue of events with timeouts. */
	struct min_heap timeheap;

	/** Stored timeval: used to avoid calling gettimeofday/clock_gettime
	 * too often. */
	struct timeval tv_cache;

	struct evutil_monotonic_timer monotonic_timer;

	/** Difference between internal time (maybe from clock_gettime) and
	 * gettimeofday. */
	struct timeval tv_clock_diff;
	/** Second in which we last updated tv_clock_diff, in monotonic time. */
	time_t last_updated_clock_diff;

#ifndef EVENT__DISABLE_THREAD_SUPPORT
	/* threading support */
	/** The thread currently running the event_loop for this base */
	unsigned long th_owner_id;
	/** A lock to prevent conflicting accesses to this event_base */
	void *th_base_lock;
	/** A condition that gets signalled when we're done processing an
	 * event with waiters on it. */
	void *current_event_cond;
	/** Number of threads blocking on current_event_cond. */
	int current_event_waiters;
#endif
	/** The event whose callback is executing right now */
	struct event_callback *current_event;

#ifdef _WIN32
	/** IOCP support structure, if IOCP is enabled. */
	struct event_iocp_port *iocp;
#endif

	/** Flags that this base was configured with */
	enum event_base_config_flag flags;

	struct timeval max_dispatch_time;
	int max_dispatch_callbacks;
	int limit_callbacks_after_prio;

	/* Notify main thread to wake up break, etc. */
	/** True if the base already has a pending notify, and we don't need
	 * to add any more. */
	int is_notify_pending;
	/** A socketpair used by some th_notify functions to wake up the main
	 * thread. */
	evutil_socket_t th_notify_fd[2];
	/** An event used by some th_notify functions to wake up the main
	 * thread. */
	struct event th_notify;
	/** A function used to wake up the main thread from another thread. */
	int (*th_notify_fn)(struct event_base *base);

	/** Saved seed for weak random number generator. Some backends use
	 * this to produce fairness among sockets. Protected by th_base_lock. */
	struct evutil_weakrand_state weakrand_seed;

	/** List of event_onces that have not yet fired. */
	LIST_HEAD(once_event_list, event_once) once_events;

};

typedef unsigned long int dev_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef unsigned long int ino_t;
typedef unsigned int mode_t;
typedef unsigned long int nlink_t;
typedef long int off_t;
typedef long int blksize_t;
typedef long int blkcnt_t;

struct stat {
	dev_t     st_dev;         /* ID of device containing file */
	ino_t     st_ino;         /* Inode number */
	mode_t    st_mode;        /* File type and mode */
	nlink_t   st_nlink;       /* Number of hard links */
	uid_t     st_uid;         /* User ID of owner */
	gid_t     st_gid;         /* Group ID of owner */
	dev_t     st_rdev;        /* Device ID (if special file) */
	off_t     st_size;        /* Total size, in bytes */
	blksize_t st_blksize;     /* Block size for filesystem I/O */
	blkcnt_t  st_blocks;      /* Number of 512B blocks allocated */

	/* Since Linux 2.6, the kernel supports nanosecond
		precision for the following timestamp fields.
		For the details before Linux 2.6, see NOTES. */

	struct timespec st_atim;  /* Time of last access */
	struct timespec st_mtim;  /* Time of last modification */
	struct timespec st_ctim;  /* Time of last status change */

#define st_atime st_atim.tv_sec      /* Backward compatibility */
#define st_mtime st_mtim.tv_sec
#define st_ctime st_ctim.tv_sec
};

struct tm
{
  int tm_sec;
  int tm_min;
  int tm_hour;
  int tm_mday;
  int tm_mon;
  int tm_year;
  int tm_wday;
  int tm_yday;
  int tm_isdst;

  long int tm_gmtoff;
  const char *tm_zone;
};

struct hostent {
	char  *h_name;            /* official name of host */
	char **h_aliases;         /* alias list */
	int    h_addrtype;        /* host address type */
	int    h_length;          /* length of address */
	char **h_addr_list;       /* list of addresses */
};
#define h_addr h_addr_list[0] /* for backward compatibility */

typedef long int off64_t;

#else

#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <ifaddrs.h>
#include <semaphore.h>
#include <getopt.h>
#include <pwd.h>
#include <event.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <rte_lcore.h>
#include <rte_ether.h>

#include "mtcp.h"
#include "mtcp_api.h"
#include "mtcp_epoll.h"

#include "lthread.h"

typedef long int off64_t;

#endif

#endif //SGX_MTCP_ENCLAVE_INTERFACE_TYPES_H
