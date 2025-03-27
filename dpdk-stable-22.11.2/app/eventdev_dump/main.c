/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2019 Intel Corporation
 */

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_eventdev.h>

/* Note - port_queue_id in xstats APIs is 8 bits,   so we have a maximum of
 * 256 ports and queues
 */
#define MAX_PORTS_QUEUES 256
static uint32_t num_ports;
uint8_t ports[MAX_PORTS_QUEUES];
static uint32_t num_queues;
uint8_t queues[MAX_PORTS_QUEUES];

int evdev_id;
bool do_dump;
bool do_device_stats;
bool do_all_ports;
bool do_all_queues;
bool do_reset;

/* No required options */
static struct option long_options[] = {
	{0, 0, 0, 0}
};

static void
usage(void)
{
	const char *usage_str =
		"Usage: eventdev_dump [options]\n"
		"Options:\n"
		" -i <dev_id>		Eventdev id, default is 0\n"
		" -D			Dump\n"
		" -P			Get port stats for all ports\n"
		" -p <port num>		Get port stats for specified port\n"
		" -Q			Get queue stats for all configured queues\n"
		" -q <queue num>	Get queue stats for specified queue\n"
		" -r			Reset stats after reading them\n"
		"\n";

	printf("%s\n", usage_str);
	exit(1);
}

static void
parse_app_args(int argc, char **argv)
{
	/* Parse cli options*/
	int option_index;
	int c;
	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv, "dDi:p:Pq:Qr", long_options,
				&option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			do_device_stats = true;
			break;
		case 'D':
			do_dump = true;
			break;
		case 'i':
			evdev_id = atoi(optarg);
			break;
		case 'p':
			ports[num_ports] = atoi(optarg);
			num_ports++;
			break;
		case 'P':
			do_all_ports = true;
			break;
		case 'q':
			queues[num_queues] = atoi(optarg);
			num_queues++;
			break;
		case 'Q':
			do_all_queues = true;
			break;
		case 'r':
			do_reset = true;
			break;
		default:
			usage();
		}
	}
}

static int
dump_all(int evdev_id)
{
	int ret = 0;

	ret = rte_event_dev_dump(evdev_id, stdout);
	return ret;
}

static void
get_stats(uint8_t dev_id,
	  enum rte_event_dev_xstats_mode mode,
	  uint8_t queue_port_id,
	  bool reset)
{
	int ret;
	struct rte_event_dev_xstats_name *xstats_names;
	uint64_t *ids;
	unsigned int size;
	int i;


	/* Get amount of storage required */
	ret = rte_event_dev_xstats_names_get(dev_id,
					     mode,
					     queue_port_id,
					     NULL, /* names */
					     NULL, /* ids */
					     0);   /* num */

	if (ret < 0)
		rte_panic("rte_event_dev_xstats_names_get err %d\n", ret);

	if (ret == 0) {
		printf(
		"No stats available for this item, mode=%d, queue_port_id=%d\n",
			mode, queue_port_id);
		return;
	}

	size = (unsigned int)ret; /* number of names */

	/* Get memory to hold stat names, IDs, and values */

	xstats_names = malloc(sizeof(struct rte_event_dev_xstats_name) * size);
	ids = malloc(sizeof(uint64_t) * size);


	if (!xstats_names || !ids)
		rte_panic("unable to alloc memory for stats retrieval\n");

	ret = rte_event_dev_xstats_names_get(dev_id, mode, queue_port_id,
					     xstats_names, ids,
					     size);
	if (ret != (int)size)
		rte_panic("rte_event_dev_xstats_names_get err %d\n", ret);

	if (!reset) {
		uint64_t *values;

		values = malloc(sizeof(uint64_t) * size);
		if (!values)
			rte_panic("unable to alloc memory for stats retrieval\n");

		ret = rte_event_dev_xstats_get(dev_id, mode, queue_port_id,
					       ids, values, size);

		if (ret != (int)size)
			rte_panic("rte_event_dev_xstats_get err %d\n", ret);

		for (i = 0; i < (int)size; i++) {
			printf("id (%"PRIu64") %s = %"PRIu64"\n",
				ids[i], &xstats_names[i].name[0], values[i]);
		}

		free(values);
	} else
		rte_event_dev_xstats_reset(dev_id, mode, queue_port_id,
					   ids, size);

	free(xstats_names);
	free(ids);
}

static void
process_stats(bool reset)
{
	unsigned int i;

	if (do_device_stats) {
		get_stats(evdev_id,
			  RTE_EVENT_DEV_XSTATS_DEVICE,
			  0,
			  reset);
	}

	if (do_all_ports) {
		for (i = 0; i < MAX_PORTS_QUEUES; i++) {
			get_stats(evdev_id,
				  RTE_EVENT_DEV_XSTATS_PORT,
				  i,
				  reset);
		}
	} else {
		for (i = 0; i < num_ports; i++) {
			get_stats(evdev_id,
				  RTE_EVENT_DEV_XSTATS_PORT,
				  ports[i],
				  reset);
		}
	}

	if (do_all_queues) {
		uint32_t num_configured_queues;

		if (rte_event_dev_attr_get(evdev_id, RTE_EVENT_DEV_ATTR_QUEUE_COUNT, &num_configured_queues))
			rte_panic("Failed to get the device's queue count\n");

		for (i = 0; i < num_configured_queues; i++) {
			get_stats(evdev_id,
				  RTE_EVENT_DEV_XSTATS_QUEUE,
				  i,
				  reset);
		}
	} else {
		for (i = 0; i < num_queues; i++) {
			get_stats(evdev_id,
				  RTE_EVENT_DEV_XSTATS_QUEUE,
				  queues[i],
				  reset);
		}
	}
}

int
main(int argc, char **argv)
{
	int diag;
	int ret;
	int i;
	char c_flag[] = "-c1";
	char n_flag[] = "-n4";
	char mp_flag[] = "--proc-type=secondary";
	char *argp[argc + 3];

	argp[0] = argv[0];
	argp[1] = c_flag;
	argp[2] = n_flag;
	argp[3] = mp_flag;

	for (i = 1; i < argc; i++)
		argp[i + 3] = argv[i];

	argc += 3;

	diag = rte_eal_init(argc, argp);
	if (diag < 0)
		rte_exit(EXIT_FAILURE, "Cannot init EAL\n");

	argc -= diag;
	argv += (diag - 3);

	/* Parse cli options*/
	parse_app_args(argc, argv);

	const uint8_t ndevs = rte_event_dev_count();
	if (ndevs == 0)
		rte_panic("No event devs found. Do you need"
			  " to pass in a --vdev flag?\n");
	if (ndevs > 1)
		printf("Warning: More than one event dev, but using idx 0\n");

	if (do_dump) {
		ret = dump_all(evdev_id);
		if (ret)
			rte_panic("dump failed with err=%d\n", ret);
	}

	/* Get and output any stats requested on the command line */
	process_stats(false);

	/* Reset the stats we just output? */
	if (do_reset)
		process_stats(true);

	return 0;
}
