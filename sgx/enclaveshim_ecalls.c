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
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <signal.h>
#include <sched.h>
#include <errno.h>

#include "sgx_urts.h"
#include "enclaveshim_ecalls.h"
#include "enclaveshim_log.h"
#include "ocalls.h"

#define MAX_PATH 256

#define MAX_ACCEPTS 25
#define MAX_CLOSES 50

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
        {
                SGX_ERROR_STACK_OVERRUN,
                "Out of stack.",
                NULL
        },
};

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
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    /* Step 1: try to retrieve the launch token saved by last transaction
     *		 *          *         if there is no token, then create a new one.
     *			 *                   */
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

void initialize_library(void) {
	if (initialize_enclave() < 0) {
		printf("Enclave initialization error!\n");
		exit(-1);
	}

	init_clock_mhz();
}

void destroy_enclave(void) {
    if (global_eid != 0) {
        printf("Destroying enclave %lu!\n", global_eid);
        sgx_destroy_enclave(global_eid);
    } else {
        printf("Cannot destroy a non-initialized enclave!\n");
    }
}

struct thread_info {     // Used as argument to thread_start()
    pthread_t thread_id; // ID returned by pthread_create()
    void *start_routine; // enclave function to be called
    void* arg;           // argument to the enclave function
};

static void *thread_start(void *arg) {
    struct thread_info *tinfo = arg;
    log_enter_ecall(__func__);
    sgx_status_t status = ecall_start_thread(global_eid, tinfo->start_routine, tinfo->arg);
    if (status != SGX_SUCCESS) {
        print_error_message(status, __func__);
    }
    log_exit_ecall(__func__);
    return NULL;
}

// NOTE: thread, attr should be allocated outside the enclave
int enclaveshim_thread_create(thread_t *thread, const thread_attr_t *attr, void *start_routine, void *arg) {
    int ret;
    struct thread_info *tinfo = malloc(sizeof(*tinfo));
    tinfo->start_routine = start_routine;
    tinfo->arg = arg;

    ret = pthread_create(thread, attr, &thread_start, tinfo);
    tinfo->thread_id = *thread;

    return ret;
}

static void* rte_eal_remote_launch_real_callback = NULL;

int rte_eal_remote_launch_fake_callback(void *arg) {
    int ret;
    log_enter_ecall(__func__);
    sgx_status_t status = ecall_rte_eal_remote_launch_call_callback(global_eid, &ret, rte_eal_remote_launch_real_callback, arg);
    if (status != SGX_SUCCESS) {
        print_error_message(status, __func__);
    }
    log_exit_ecall(__func__);
    return ret;
}

void* enclaveshim_register_rte_eal_remote_launch_callback(void* real_callback) {
    rte_eal_remote_launch_real_callback = real_callback;
    return rte_eal_remote_launch_fake_callback;
}

int main_wrapper(int argc, char **argv) {
    if (global_eid == 0) {
        initialize_library();
    }

    int ret;
    log_enter_ecall(__func__);
    sgx_status_t status = ecall_main_wrapper(global_eid, &ret, argc, argv);
    if (status != SGX_SUCCESS) {
        print_error_message(status, __func__);
    }
    log_exit_ecall(__func__);
    return ret;
}
