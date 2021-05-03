# Build
## mTCP
### W/ SGX
Makefile.sgx compiles the mtcp library object files and enclaveshim-related files
```
$ cd 19-secure-network-path/sgx-mtcp
$ make -f Makefile.sgx SGX_MODE=HW SGX_PRERELEASE=1
```

### W/O SGX
Makefile.nosgx creates the mtcp library
```
$ cd 19-secure-network-path/sgx-mtcp
$ make -f Makefile.nosgx
```

### Options
#### ENABLE_UCTX
Use lthread instead of pthread

Same option should be enabled when the application is compiled

## Application
Each application has its own Makefile.sgx and Makefile.nosgx

### W/ SGX
Makefile.sgx creates the signed-enclave and the executable file
```
$ cd 19-secure-network-path/sgx-mtcp/app/xxxx
$ make -f Makefile.sgx SGX_MODE=HW SGX_PRERELEASE=1
```

### W/O SGX
Makefile.nosgx creates the executable file
```
$ cd 19-secure-network-path/sgx-mtcp/app/xxxx
$ make -f Makefile.nosgx
```

### Options
#### ENABLE_UCTX
Use lthread instead of pthread

Same option should be enabled when the mTCP is compiled


# Evaluation
## Server and Client
### MTU
```
$ ip link set enp1s0f0 mtu 9600
```
### microbench
Server
```
$ ./mtcpserver-nosgx -N 1 -f ./mtcpserver.conf -s 1 -r 1 -R 1
```

Client
```
$ ./mtcpclient 192.168.50.1 -N 1 -c 50 -f ./mtcpclient.conf -s 1 -r 1 -R 1
```
### memcached
Server
```
$ ./memcached -u root -t 1 -M
```

Client
```
$ ./memcached_client 192.168.50.1 -N 1 -c 10 -f mtcp.conf -v 1024 -k 800000 -r 95 -l
```
