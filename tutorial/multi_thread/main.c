
#include <stdio.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_log.h>

static int thread(__attribute__((unused))void *arg)
{
	unsigned lcore_id = rte_lcore_id();
	for (size_t i=0; i<5; i++) {
		printf("thread on lcore%u\n", lcore_id);
		sleep(1);
	}
	return 0;
}

int main(int argc, char **argv)
{
	rte_log_set_global_level(RTE_LOG_EMERG);
	int ret = rte_eal_init(argc, argv);
	if (ret < 0) return -1;

	rte_eal_remote_launch(thread, NULL, 1);
	rte_eal_remote_launch(thread, NULL, 2);
	rte_eal_mp_wait_lcore();
	return 0;
}

