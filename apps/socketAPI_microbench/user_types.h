#ifndef USER_TYPES_H_
#define USER_TYPES_H_

typedef unsigned int __socklen_t;
typedef __socklen_t socklen_t;

typedef long int __ssize_t;
typedef __ssize_t ssize_t;

typedef unsigned short int sa_family_t;

struct sockaddr
  {
    sa_family_t sa_family;
    char sa_data[14];
  };


#ifndef DONT_DEFINE_STRUCTS
typedef long int __fd_mask;
typedef struct
{
	__fd_mask fds_bits[1024 / (8 * (int) sizeof (__fd_mask))];
} fd_set;

typedef long int __time_t;
typedef long int __suseconds_t;

struct timeval
{
  __time_t tv_sec;
  __suseconds_t tv_usec;
};
#endif

#endif
