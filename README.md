# SGX-mTCP

SGX-mTCP is a port of the mTCP user-level TCP library to Intel SGX.
Please refer to [this technical report](sgx-mtcp.pdf) for more information.

## Installation

1. Download the DPDK submodule.

```bash
$ git submodule init
$ git submodule update
```

2. Activate the Mellanox PMD module in DPDK by adding the following line to `dpdk/config/defconfig_x86_64-native-linuxapp-gcc`:

```bash
CONFIG_RTE_LIBRTE_MLX5_PMD=y
```

Note: the makefiles of SGX-mTCP expect this module to be present at compile time.

3. Compile DPDK and setup environments

```bash
$ ./setup_mtcp_dpdk_env.sh
15 # compile DPDK
18 # insert IGB UIO module; not needed for Mellanox NICs
21 # mount hugepages; or 22 if you have a NUMA machine
24 # bind NIC to IGB UIO module; not needed for Mellanox NICs
35 # exit
y  # even if you don't have an Intel NIC, the dpdk-iface module is required by mTCP
```

3. Configure the IP address of the NIC you will use with DPDK.

E.g.,
```bash
$ sudo ifconfig dpdk0 192.168.10.1
$ sudo ifconfig enp1s0f0 192.168.10.2
```

4. Compile SGX-mTCP

SGX-mTCP can be compiled in 2 ways: with (`Makefile.nosgx`) and without SGX (`Makefile.sgx`).
There are 2 levels of makefiles: (1) in the root directory, to compile the mtcp library; and (2) one set for each application in the `apps` directory.

When compiling with SGX in hardware mode, you need to add the `SGX_PRERELEASE=1 SGX_MODE=HW` variables as follows:
```bash
$ SGX_PRERELEASE=1 SGX_MODE=HW make -f Makefile.sgx
```

Compile without SGX is simpler:
```bash
$ make -f Makefile.nosgx
```

## Execution

The following section details how to start the mTCP microbenchmark application (please refer to the original documentation of mTCP for other applications, or the Memcached documentation for the memcached application).

1. Compilation

We assume the mTCP library has already been compiled.

```bash
$ cd apps/mtcp_microbenchmark
$ SGX_PRERELEASE=1 SGX_MODE=HW make -f Makefile.sgx
$ make -f Makefile.nosgx # or this line if you compile without SGX
```

2. Configuration

Please edit the `mtcpclient.conf` or `mtcpserver.conf` files to set the correct mTCP configuration, in particular the `port` and `stat_print` lines. If you use a Mellanox NIC, please enter the real interface name (e.g., enp1s0f0).

3. Start 

Note that both the client and server applications need to be installed on different machines.
We assume the server IP address is 192.168.10.1.

To start the server:
```bash
$ sudo ./mtcpserver -N 1 -f ./mtcpserver.conf -s 1 -r 1 -R 1
$ sudo ./mtcpserver-nosgx -N 1 -f ./mtcpserver.conf -s 1 -r 1 -R 1 # if you don't use SGX
```

To start the client:
```bash
$ sudo ./mtcpclient 192.168.10.1 -N 1 -c 1 -f ./mtcpclient.conf -s 1 -r 1 -R 0
```

4. Executable arguments

The server arguments are as follows:
```bash
./mtcpserver -N <num cores> -f <mtcp config file> -s <send request size> -r <receive request size> -R <num requests per TCP connection; 0 for persistent connections>
```

The client arguments are as follows:
```bash
./mtcpclient <server IP> -N <num cores> -f <mtcp config file> -s <send request size> -r <receive request size> -R <num requests per TCP connection; 0 for persistent connections>
```

## Options

SGX-mTCP includes the lthread user-level threading library, both with and without Intel SGX. This removes thread context switch between the mTCP and application threads executing on the same CPU and improves performance.

It is activated by default. To deactivate it, please remove the `-DENABLE_UCTX` flag in the makefiles (both mTCP library and application), clean and recompile.

## Troubleshooting

### Fallthrough compilation error

On recent gcc versions the compilation of DPDK might fail with the following error: `dpdk/x86_64-native-linuxapp-gcc/build/kernel/linux/igb_uio/igb_uio.c:230:6: error: this statement may fall through [-Werror=implicit-fallthrough=]`.

To solve this, apply the following patch:
```c
diff --git a/kernel/linux/igb_uio/igb_uio.c b/kernel/linux/igb_uio/igb_uio.c
index 3cf394bdf..a40cdcc2c 100644
--- a/kernel/linux/igb_uio/igb_uio.c
+++ b/kernel/linux/igb_uio/igb_uio.c
@@ -236,6 +236,7 @@ igbuio_pci_enable_interrupts(struct rte_uio_pci_dev *udev)
                }
 #endif
 
+               fallthrough;
        /* fall back to MSI */
        case RTE_INTR_MODE_MSI:
 #ifndef HAVE_ALLOC_IRQ_VECTORS
@@ -255,6 +256,7 @@ igbuio_pci_enable_interrupts(struct rte_uio_pci_dev *udev)
                        break;
                }
 #endif
+               fallthrough;
        /* fall back to INTX */
        case RTE_INTR_MODE_LEGACY:
                if (pci_intx_mask_supported(udev->pdev)) {
@@ -265,6 +267,7 @@ igbuio_pci_enable_interrupts(struct rte_uio_pci_dev *udev)
                        break;
                }
                dev_notice(&udev->pdev->dev, "PCI INTX mask not supported\n");
+               fallthrough;
        /* fall back to no IRQ */
        case RTE_INTR_MODE_NONE:
                udev->mode = RTE_INTR_MODE_NONE;
```

### No hugepages

When starting the application, if it stops with a message indicating that there are no hugepages, please run the `setup_mtcp_dpdk_env.sh` script to install the hugepages.

### Application hangs

If the application hangs, it might be because you have disabled lthread (`#-DENABLE_UCTX`) in one makefile but not the other. Please adujst the flag and recompile.

## References

- sgx-mtcp: executing the user-level mTCP stack inside an Intel SGX enclave. Keita Aihara, Pierre-Louis Aublin, and Kenji Kono. May 2021. [PDF](sgx-mtcp.pdf)

- A Secure Network Stack for the Untrusted Cloud. Keita Aihara, Pierre-Louis Aublin, and Kenji Kono. In the Fiftenn European Conference on Computer Systems (EuroSys). Poster session. April 2020. 

- secureTCP: Securing the TCP/IP stack using a Trusted Execution Environment. Keita Aihara, Pierre-Louis Aublin, and Kenji Kono. In the Information Processing Society of Japan System Software and Operating System conference (ComSys). December 2019. Best young research award.
