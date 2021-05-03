#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <numa.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <assert.h>
#include <rte_lcore.h>
#include "mtcp_api.h"
#ifndef DISABLE_DPDK
#include <mtcp.h>
#endif


#ifdef COMPILE_WITH_INTEL_SGX
#include "enclaveshim_ocalls.h"
#include "enclaveshim_config.h"
#else
#define my_printf(format, ...) printf(format, ##__VA_ARGS__)
#define syscall1(number, ...) syscall(number, ##__VA_ARGS__)
#endif

#define MAX_FILE_NAME 1024

/*----------------------------------------------------------------------------*/
inline int
GetNumCPUs()
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}
/*----------------------------------------------------------------------------*/
pid_t
Gettid()
{
	return syscall1(__NR_gettid);
}
/*----------------------------------------------------------------------------*/
#ifndef DISABLE_DPDK
int count_set_bits(size_t n)
{
    int count = 0;
    while (n) {
        count += n & 1;
        n >>= 1;
    }
    return count;
}
#endif
inline int
whichCoreID(int thread_no)
{
#ifndef DISABLE_DPDK
	int i, cpu_id;
	if ((unsigned long)CONFIG._cpumask == 0)
		return thread_no;
	else {
		//PL: before it was
		//			int limit =  mpz_popcount(CONFIG._cpumask);
		//Not sure if the semantics is the same...
		my_printf("%s:%s please check semantics of mpz_popcount and fix this code if there is any strange behaviour\n", __FILE__, __func__);
		int limit =  count_set_bits(CONFIG._cpumask);

		for (cpu_id = 0, i = 0; i < limit; cpu_id++)
			if (CONFIG._cpumask >> cpu_id & 0x1) {
				if (thread_no == i)
					return cpu_id;
				i++;
			}
	}
#endif
	return thread_no;
}
/*----------------------------------------------------------------------------*/
int ecall_mtcp_core_affinitize(int cpu) {
	int appcpu = cpu;

#if defined	COMPILE_WITH_INTEL_SGX && defined MTCP_APP_THREAD_SEPARATION
	size_t n;
	n = GetNumCPUs();
	cpu = cpu + (n >> 1);
#endif
	my_printf("[%s] App core %d mtcp core %d\n", __func__, appcpu, cpu);

	return mtcp_core_affinitize(cpu);
}
int
mtcp_core_affinitize(int cpu)
{

	cpu_set_t cpus;
	size_t n;
	int ret;

	n = GetNumCPUs();

	cpu = whichCoreID(cpu);

	if (cpu < 0 || cpu >= (int) n) {
		errno = -EINVAL;
		return -1;
	}

	CPU_ZERO(&cpus);
	CPU_SET((unsigned)cpu, &cpus);

#ifndef DISABLE_DPDK
	ret = rte_thread_set_affinity(&cpus);
#else
	struct bitmask *bmask;
	FILE *fp;
	char sysfname[MAX_FILE_NAME];
	int phy_id;

	ret = sched_setaffinity(Gettid(), sizeof(cpus), &cpus);

	if (numa_max_node() == 0)
		return ret;

	bmask = numa_bitmask_alloc(numa_max_node() + 1);
	assert(bmask);

	/* read physical id of the core from sys information */
	snprintf(sysfname, MAX_FILE_NAME - 1,
			"/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
	fp = fopen(sysfname, "r");
	if (!fp) {
		perror(sysfname);
		errno = EFAULT;
		return -1;
	}
	ret = fscanf(fp, "%d", &phy_id);
	if (ret != 1) {
		fclose(fp);
		perror("Fail to read core id");
		errno = EFAULT;
		return -1;
	}

	numa_bitmask_setbit(bmask, phy_id);
	numa_set_membind(bmask);
	numa_bitmask_free(bmask);

	fclose(fp);
#endif
	return ret;
}
int
mtcp_core_affinitize_for_app(int cpu)
{

	cpu_set_t cpus;
	size_t n;
	int ret;

	n = GetNumCPUs();

#ifdef MTCP_APP_THREAD_SEPARATION
	cpu = cpu + (n >> 1);
#endif

	cpu = whichCoreID(cpu);

	if (cpu < 0 || cpu >= (int) n) {
		errno = -EINVAL;
		return -1;
	}

	CPU_ZERO(&cpus);
	CPU_SET((unsigned)cpu, &cpus);

#ifndef DISABLE_DPDK
	ret = rte_thread_set_affinity(&cpus);
#else
	struct bitmask *bmask;
	FILE *fp;
	char sysfname[MAX_FILE_NAME];
	int phy_id;

	ret = sched_setaffinity(Gettid(), sizeof(cpus), &cpus);

	if (numa_max_node() == 0)
		return ret;

	bmask = numa_bitmask_alloc(numa_max_node() + 1);
	assert(bmask);

	/* read physical id of the core from sys information */
	snprintf(sysfname, MAX_FILE_NAME - 1,
			"/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
	fp = fopen(sysfname, "r");
	if (!fp) {
		perror(sysfname);
		errno = EFAULT;
		return -1;
	}
	ret = fscanf(fp, "%d", &phy_id);
	if (ret != 1) {
		fclose(fp);
		perror("Fail to read core id");
		errno = EFAULT;
		return -1;
	}

	numa_bitmask_setbit(bmask, phy_id);
	numa_set_membind(bmask);
	numa_bitmask_free(bmask);

	fclose(fp);
#endif
	return ret;
}
