//
// Created by pl on 19/04/29.
//

#ifndef SGX_MTCP_THREAD_WRAPPER_H
#define SGX_MTCP_THREAD_WRAPPER_H

#ifdef COMPILE_WITH_INTEL_SGX

#include <sys/time.h>
#include <semaphore.h>

#include <sgx_thread.h>
#include <sgx_spinlock.h>

typedef sgx_spinlock_t thread_spinlock_t;
typedef sgx_thread_mutex_t thread_mutex_t;
typedef sgx_thread_mutexattr_t thread_mutexattr_t;
typedef sgx_thread_cond_t thread_cond_t;
typedef sgx_thread_condattr_t thread_condattr_t;
typedef sgx_thread_t thread_t;
typedef void* thread_attr_t;
typedef unsigned int thread_key_t;

#else

#include <pthread.h>
#include <signal.h>
#include <semaphore.h>

typedef pthread_spinlock_t thread_spinlock_t;
typedef pthread_mutex_t thread_mutex_t;
typedef pthread_mutexattr_t thread_mutexattr_t;
typedef pthread_cond_t thread_cond_t;
typedef pthread_condattr_t thread_condattr_t;
typedef pthread_t thread_t;
typedef pthread_attr_t thread_attr_t;
typedef pthread_key_t thread_key_t;

#endif


inline int thread_attr_init(thread_attr_t *attr);

inline int thread_spin_init(thread_spinlock_t *lock, int pshared);

inline int thread_spin_destroy(thread_spinlock_t *lock);

inline int thread_spin_lock(thread_spinlock_t *lock);

inline int thread_spin_unlock(thread_spinlock_t *lock);

inline int thread_mutex_init(thread_mutex_t *restrict mutex, const thread_mutexattr_t *restrict attr);

inline int thread_mutex_destroy(thread_mutex_t *mutex);

inline int thread_mutex_trylock(thread_mutex_t *mutex);

inline int thread_mutex_lock(thread_mutex_t *mutex);

inline int thread_mutex_unlock(thread_mutex_t *mutex);

void thread_exit(void *retval);

inline int thread_cond_init(thread_cond_t *restrict cond, const thread_condattr_t *restrict attr);

inline int thread_cond_destroy(thread_cond_t *cond);

inline int thread_cond_wait(thread_cond_t *restrict cond, thread_mutex_t *restrict mutex);

int thread_cond_timedwait(thread_cond_t *restrict cond, thread_mutex_t *restrict mutex, const struct timespec *restrict abstime);

inline int thread_cond_signal(thread_cond_t *cond);

inline thread_t thread_self(void);

int thread_create(thread_t *thread, const thread_attr_t *attr, void *(*start_routine) (void *), void *arg);

int thread_join(thread_t thread, void **retval);

int thread_kill(thread_t thread, int sig);

int thread_sem_init(sem_t *sem, int pshared, unsigned int value);

int thread_sem_destroy(sem_t *sem);

int thread_sem_wait(sem_t *sem);

int thread_sem_post(sem_t *sem);

int thread_key_create(thread_key_t *key, void (*destr_function) (void *));

int thread_setspecific(thread_key_t key, const void *ptr);

void * thread_getspecific(thread_key_t key);

#endif //SGX_MTCP_THREAD_WRAPPER_H
