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

#ifndef ENCLAVE_SHIM_H_
#define ENCLAVE_SHIM_H_

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"

void print_error_message(sgx_status_t ret, const char* fn);
int initialize_enclave(void);
void destroy_enclave(void);

/********** enclave interface *********/

#include <unistd.h>

#include "mtcp_api.h"
#include "mtcp_epoll.h"

// NOTE: thread, attr should be allocated outside the enclave
int enclaveshim_thread_create(pthread_t *thread, const pthread_attr_t *attr, void *start_routine, void *arg);

void* enclaveshim_register_rte_eal_remote_launch_callback(void* real_callback);

int main_wrapper(int argc, char **argv);
#endif
