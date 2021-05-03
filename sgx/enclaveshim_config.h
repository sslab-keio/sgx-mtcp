/*
 * This file contains important macros to configure sgx-mtcp behaviour
 */

#ifndef ENCLAVESHIM_CONFIG_H
#define ENCLAVESHIM_CONFIG_H

// define this flag to log ecalls and ocalls
#undef LOG_ENCLAVE_ENTER_EXIT

// separate the mtcp and app threads on different cores
#undef MTCP_APP_THREAD_SEPARATION

#endif
