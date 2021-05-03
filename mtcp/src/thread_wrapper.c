//
// Created by pl on 19/04/29.
//

#include "thread_wrapper.h"

#ifdef COMPILE_WITH_INTEL_SGX
#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "enclave_t.h"
#include "sgx_trts.h"

#include "enclaveshim_ocalls.h"
#endif

inline int thread_attr_init(thread_attr_t *attr) {
#ifdef COMPILE_WITH_INTEL_SGX
    my_printf("%s:%s ocall to be implemented!\n", __FILE__, __func__);
    return 0;
#else
    return pthread_attr_init(attr);
#endif
}

inline int thread_spin_init(thread_spinlock_t *lock, int pshared) {
#ifdef COMPILE_WITH_INTEL_SGX
    *lock = SGX_SPINLOCK_INITIALIZER;
    return 0;
#else
    return pthread_spin_init(lock, pshared);
#endif
}

inline int thread_spin_destroy(thread_spinlock_t *lock) {
#ifdef COMPILE_WITH_INTEL_SGX
    return 0;
#else
    return pthread_spin_destroy(lock);
#endif
}

inline int thread_spin_lock(thread_spinlock_t *lock) {
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_spin_lock(lock);
#else
    return pthread_spin_lock(lock);
#endif
}

inline int thread_spin_unlock(thread_spinlock_t *lock) {
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_spin_unlock(lock);
#else
    return pthread_spin_unlock(lock);
#endif
}

inline int thread_mutex_init(thread_mutex_t *restrict mutex, const thread_mutexattr_t *restrict attr) {
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_thread_mutex_init(mutex, attr);
#else
    return pthread_mutex_init(mutex, attr);
#endif
}

inline int thread_mutex_destroy(thread_mutex_t *mutex) {
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_thread_mutex_destroy(mutex);
#else
    return pthread_mutex_destroy(mutex);
#endif
}

inline int thread_mutex_trylock(thread_mutex_t *mutex) {
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_thread_mutex_trylock(mutex);
#else
    return pthread_mutex_trylock(mutex);
#endif
}

inline int thread_mutex_lock(thread_mutex_t *mutex) {
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_thread_mutex_lock(mutex);
#else
    return pthread_mutex_lock(mutex);
#endif
}

inline int thread_mutex_unlock(thread_mutex_t *mutex) {
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_thread_mutex_unlock(mutex);
#else
    return pthread_mutex_unlock(mutex);
#endif
}

void thread_exit(void *ret) {
#ifdef COMPILE_WITH_INTEL_SGX
    sgx_status_t status;
    status = ocall_pthread_exit(ret);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
    }
#else
    return pthread_exit(ret);
#endif
}

inline int thread_cond_init(thread_cond_t *restrict cond, const thread_condattr_t *restrict attr) {
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_thread_cond_init(cond, attr);
#else
    return pthread_cond_init(cond, attr);
#endif
}

inline int thread_cond_destroy(thread_cond_t *cond) {
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_thread_cond_destroy(cond);
#else
    return pthread_cond_destroy(cond);
#endif
}

inline int thread_cond_wait(thread_cond_t *restrict cond, thread_mutex_t *restrict mutex) {
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_thread_cond_wait(cond, mutex);
#else
    return pthread_cond_wait(cond, mutex);
#endif
}

int thread_cond_timedwait(thread_cond_t *restrict cond, thread_mutex_t *restrict mutex, const struct timespec *restrict abstime) {
#ifdef COMPILE_WITH_INTEL_SGX
    //TODO -- maybe an ocall? Or forget about the time?
    my_printf("%s:%s HAS TO BE IMPLEMENTED!!!\n", __FILE__, __func__);
    return 0;
#else
    return pthread_cond_timedwait(cond, mutex, abstime);
#endif
}

inline int thread_cond_signal(thread_cond_t *cond) {
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_thread_cond_signal(cond);
#else
    return pthread_cond_signal(cond);
#endif
}

inline thread_t thread_self(void) {
#ifdef COMPILE_WITH_INTEL_SGX
    return sgx_thread_self();
#else
    return pthread_self();
#endif
}

void ecall_start_thread(void *start_routine, void *arg) {
    // TODO: Limit the start_routine to prevent arbitrary execution inside the enclave
    void *(*f) (void *) = (void *(*) (void *))start_routine;
    f(arg);
}

int thread_create(thread_t *thread, const thread_attr_t *attr, void *(*start_routine) (void *), void *arg) {
#ifdef COMPILE_WITH_INTEL_SGX
    int ret;
    sgx_status_t status;
    status = ocall_pthread_create(&ret, thread, attr, (void*)start_routine, arg);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
#else
    return pthread_create(thread, attr, start_routine, arg);
#endif
}

int thread_join(thread_t thread, void **thread_return) {
#ifdef COMPILE_WITH_INTEL_SGX
    int ret;
    sgx_status_t status;
    status = ocall_pthread_join(&ret, thread, thread_return);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
#else
    return pthread_join(thread, thread_return);
#endif
}

int thread_kill(thread_t thread, int sig) {
#ifdef COMPILE_WITH_INTEL_SGX
    //TODO either an ocall or we disable this signaling possibility
    my_printf("%s:%s HAS TO BE IMPLEMENTED!!!\n", __FILE__, __func__);
    return 0;
#else
    return pthread_kill(thread, sig);
#endif
}

int thread_sem_init(sem_t *sem, int pshared, unsigned int value) {
#ifdef COMPILE_WITH_INTEL_SGX
    int ret;
    sgx_status_t status;
    status = ocall_sem_init(&ret, sem, pshared, value);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
#else
    return sem_init(sem, pshared, value);
#endif
}

int thread_sem_destroy(sem_t *sem) {
#ifdef COMPILE_WITH_INTEL_SGX
    int ret;
    sgx_status_t status;
    status = ocall_sem_destroy(&ret, sem);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
#else
    return sem_destroy(sem);
#endif
}

int thread_sem_wait(sem_t *sem) {
#ifdef COMPILE_WITH_INTEL_SGX
    int ret;
    sgx_status_t status;
    status = ocall_sem_wait(&ret, sem);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
#else
    return sem_wait(sem);
#endif
}

int thread_sem_post(sem_t *sem) {
#ifdef COMPILE_WITH_INTEL_SGX
    int ret;
    sgx_status_t status;
    status = ocall_sem_post(&ret, sem);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
#else
    return sem_post(sem);
#endif
}

int thread_key_create(thread_key_t *key, void (*destr_function) (void *)) {
#ifdef COMPILE_WITH_INTEL_SGX
    int ret;
    sgx_status_t status;
    status = ocall_pthread_key_create(&ret, key, destr_function);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
#else
    return pthread_key_create(key, destr_function);
#endif
}

int thread_setspecific(thread_key_t key, const void *ptr) {
#ifdef COMPILE_WITH_INTEL_SGX
    int ret;
    sgx_status_t status;
    status = ocall_pthread_setspecific(&ret, key, ptr);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = -1;
    }
    return ret;
#else
    return pthread_setspecific(key, ptr);
#endif
}

void * thread_getspecific(thread_key_t key) {
#ifdef COMPILE_WITH_INTEL_SGX
void *ret;
    sgx_status_t status;
    status = ocall_pthread_getspecific(&ret, key);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        ret = NULL;
    }
    return ret;
#else
    return pthread_getspecific(key);
#endif
}
