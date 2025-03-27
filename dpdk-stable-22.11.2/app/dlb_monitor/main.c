/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019-2021 Intel Corporation
 */

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_eventdev.h>
#include <rte_string_fns.h>

/* Note: port_queue_id in xstats APIs is 8 bits, hence maximum of 256 */
#define MAX_PORTS_QUEUES 256
static uint32_t num_ports;
static uint32_t num_queues;
static struct rte_event_port_conf port_confs[MAX_PORTS_QUEUES];
static struct rte_event_queue_conf queue_confs[MAX_PORTS_QUEUES];

static int dev_id;
static bool do_reset;
static bool do_watch;
static bool skip_zero;

static uint32_t measure_time_us = 1 * US_PER_S;

static void
usage(void)
{
	const char *usage_str =
		"Usage: dlb_monitor [options]\n"
		"Options:\n"
		" -i <dev_id>	Eventdev id (default: 0)\n"
		" -r		Reset stats after displaying them\n"
		" -t <duration> Measurement duration (seconds) (min: 1s, default: 1s)\n"
		" -w            Repeatedly print stats\n"
		" -z            Don't print ports or queues with 0 enqueue/dequeue/depth stats\n"
		"\n";

	printf("%s\n", usage_str);
	exit(1);
}

static void
parse_app_args(int argc, char **argv)
{
	int option_index, c;

	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv, "i:rt:wz", NULL,
				&option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'i':
			dev_id = atoi(optarg);
			break;
		case 'r':
			do_reset = true;
			break;
		case 't':
			if (atoi(optarg) < 1)
				usage();
			measure_time_us = atoi(optarg) * US_PER_S;
			break;
		case 'w':
			do_watch = true;
			break;
		case 'z':
			skip_zero = true;
			break;
		default:
			usage();
		}
	}
}

static const char * const dev_xstat_strs[] = {
	"dev_inflight_events",
	"dev_nb_events_limit",
	"dev_ldb_pool_size",
	"dev_dir_pool_size",
	"dev_pool_size",
};

enum dlb_dev_xstats {
	DEV_INFL_EVENTS,
	DEV_NB_EVENTS_LIMIT,
	DEV_LDB_POOL_SIZE,
	DEV_DIR_POOL_SIZE,
	DEV_POOL_SIZE,
};

static const char * const port_xstat_strs[] = {
	"tx_ok",
	"tx_new",
	"tx_fwd",
	"tx_rel",
	"tx_sched_ordered",
	"tx_sched_unordered",
	"tx_sched_atomic",
	"tx_sched_directed",
	"tx_invalid",
	"tx_nospc_ldb_hw_credits",
	"tx_nospc_dir_hw_credits",
	"tx_nospc_hw_credits",
	"tx_nospc_inflight_max",
	"tx_nospc_new_event_limit",
	"tx_nospc_inflight_credits",
	"outstanding_releases",
	"max_outstanding_releases",
	"total_polls",
	"zero_polls",
	"rx_ok",
	"rx_sched_ordered",
	"rx_sched_unordered",
	"rx_sched_atomic",
	"rx_sched_directed",
	"rx_sched_invalid",
	"is_configured",
	"is_load_balanced",
};

enum dlb_port_xstats {
	TX_OK,
	TX_NEW,
	TX_FWD,
	TX_REL,
	TX_SCHED_ORDERED,
	TX_SCHED_UNORDERED,
	TX_SCHED_ATOMIC,
	TX_SCHED_DIRECTED,
	TX_SCHED_INVALID,
	TX_NOSPC_LDB_HW_CREDITS,
	TX_NOSPC_DIR_HW_CREDITS,
	TX_NOSPC_HW_CREDITS,
	TX_NOSPC_INFL_MAX,
	TX_NOSPC_NEW_EVENT_LIM,
	TX_NOSPC_INFL_CREDITS,
	OUTSTANDING_RELEASES,
	MAX_OUTSTANDING_RELEASES,
	TOTAL_POLLS,
	ZERO_POLLS,
	RX_OK,
	RX_SCHED_ORDERED,
	RX_SCHED_UNORDERED,
	RX_SCHED_ATOMIC,
	RX_SCHED_DIRECTED,
	RX_SCHED_INVALID,
	IS_CONFIGURED,
	PORT_IS_LOAD_BALANCED,
};

static const char * const queue_xstat_strs[] = {
	"current_depth",
	"is_load_balanced",
};

enum dlb_queue_xstats {
	CURRENT_DEPTH,
	QUEUE_IS_LOAD_BALANCED,
};

uint64_t dev_xstat_ids[RTE_DIM(dev_xstat_strs)];
uint64_t port_xstat_ids[MAX_PORTS_QUEUES][RTE_DIM(port_xstat_strs)];
uint64_t queue_xstat_ids[MAX_PORTS_QUEUES][RTE_DIM(queue_xstat_strs)];

uint64_t dev_xstat_vals[RTE_DIM(dev_xstat_strs)];
uint64_t port_xstat_vals[MAX_PORTS_QUEUES][RTE_DIM(port_xstat_strs)];
uint64_t queue_xstat_vals[MAX_PORTS_QUEUES][RTE_DIM(queue_xstat_strs)] = {0};

uint64_t prev_sched_throughput[MAX_PORTS_QUEUES] = {0};

#define MAX_QUEUES_PER_PORT 8
struct port_link_info {
	int num_links;
	uint8_t queues[MAX_QUEUES_PER_PORT];
	uint8_t priorities[MAX_QUEUES_PER_PORT];
};

struct port_link_info port_links[MAX_PORTS_QUEUES];

static void
get_xstats_ids(uint8_t dev_id,
	       enum rte_event_dev_xstats_mode mode,
	       const char * const *names,
	       uint64_t *ids,
	       unsigned int len,
	       uint8_t queue_port_id)
{
	struct rte_event_dev_xstats_name *xstats_names;
	uint64_t *xstats_ids;
	unsigned int size, i, j;
	int ret;

	/* Get amount of storage required */
	ret = rte_event_dev_xstats_names_get(dev_id,
					     mode,
					     queue_port_id,
					     NULL, /* names */
					     NULL, /* ids */
					     0);   /* num */
	if (ret <= 0)
		rte_panic("rte_event_dev_xstats_names_get err %d\n", ret);

	size = (unsigned int)ret;

	xstats_names = malloc(sizeof(struct rte_event_dev_xstats_name) * size);
	xstats_ids = malloc(sizeof(uint64_t) * size);

	if (!xstats_names || !xstats_ids)
		rte_panic("unable to alloc memory for stats retrieval\n");

	ret = rte_event_dev_xstats_names_get(dev_id, mode, queue_port_id,
					     xstats_names, xstats_ids,
					     size);
	if (ret != (int)size)
		rte_panic("rte_event_dev_xstats_names_get err %d\n", ret);

	for (i = 0; i < len; i++) {
		char name[RTE_EVENT_DEV_XSTATS_NAME_SIZE];

		if (mode == RTE_EVENT_DEV_XSTATS_DEVICE)
			rte_strlcpy(name,
				    names[i],
				    RTE_EVENT_DEV_XSTATS_NAME_SIZE - 1);
		else if (mode == RTE_EVENT_DEV_XSTATS_PORT)
			snprintf(name,
				 RTE_EVENT_DEV_XSTATS_NAME_SIZE - 1,
				 "port_%u_%s",
				 queue_port_id,
				 names[i]);
		else
			snprintf(name,
				 RTE_EVENT_DEV_XSTATS_NAME_SIZE - 1,
				 "qid_%u_%s",
				 queue_port_id,
				 names[i]);

		for (j = 0; j < size; j++) {
			if (strncmp(name,
				    xstats_names[j].name,
				    RTE_EVENT_DEV_XSTATS_NAME_SIZE) == 0) {
				ids[i] = xstats_ids[j];
				break;
			}
		}

		if (j == size)
			rte_panic("Couldn't find xstat %s\n", name);
	}

	free(xstats_names);
	free(xstats_ids);
}

static void
init_xstats(void)
{
	unsigned int i;

	/* Lookup xstats IDs in advance */
	get_xstats_ids(dev_id,
		       RTE_EVENT_DEV_XSTATS_DEVICE,
		       dev_xstat_strs,
		       dev_xstat_ids,
		       RTE_DIM(dev_xstat_strs),
		       0);

	for (i = 0; i < num_ports; i++) {
		get_xstats_ids(dev_id,
			       RTE_EVENT_DEV_XSTATS_PORT,
			       port_xstat_strs,
			       port_xstat_ids[i],
			       RTE_DIM(port_xstat_strs),
			       i);
	}

	for (i = 0; i < num_queues; i++) {
		get_xstats_ids(dev_id,
			       RTE_EVENT_DEV_XSTATS_QUEUE,
			       queue_xstat_strs,
			       queue_xstat_ids[i],
			       RTE_DIM(queue_xstat_strs),
			       i);
	}

	/* Initialize prev_sched_throughput[i] */
	for (i = 0; i < num_ports; i++) {
		int ret;
		ret = rte_event_dev_xstats_get(dev_id,
					       RTE_EVENT_DEV_XSTATS_PORT,
					       i,
					       port_xstat_ids[i],
					       port_xstat_vals[i],
					       RTE_DIM(port_xstat_strs));
		if (ret != RTE_DIM(port_xstat_strs))
			rte_panic("Failed to get port %u's xstats (ret: %d)\n",
				  i, ret);
		prev_sched_throughput[i] = port_xstat_vals[i][RX_OK];
	}
}

static void
collect_config(void)
{
	uint32_t attr_id;
	unsigned int i;
	int ret;

	attr_id = RTE_EVENT_DEV_ATTR_PORT_COUNT;
	if (rte_event_dev_attr_get(dev_id, attr_id, &num_ports))
		rte_panic("Failed to get the device's port count\n");

	attr_id = RTE_EVENT_DEV_ATTR_QUEUE_COUNT;
	if (rte_event_dev_attr_get(dev_id, attr_id, &num_queues))
		rte_panic("Failed to get the device's queue count\n");

	init_xstats();

	for (i = 0; i < num_ports; i++) {
		uint32_t attr;

		attr_id = RTE_EVENT_PORT_ATTR_NEW_EVENT_THRESHOLD;
		if (rte_event_port_attr_get(dev_id, i, attr_id, &attr))
			rte_panic("Failed to get port %u's new event threshold\n",
				  i);

		port_confs[i].new_event_threshold = attr;

		attr_id = RTE_EVENT_PORT_ATTR_ENQ_DEPTH;
		if (rte_event_port_attr_get(dev_id, i, attr_id, &attr))
			rte_panic("Failed to get port %u's enqueue depth\n",
				  i);

		port_confs[i].enqueue_depth = attr;

		attr_id = RTE_EVENT_PORT_ATTR_DEQ_DEPTH;
		if (rte_event_port_attr_get(dev_id, i, attr_id, &attr))
			rte_panic("Failed to get port %u's dequeue depth\n",
				  i);

		port_confs[i].dequeue_depth = attr;

		attr_id = RTE_EVENT_PORT_ATTR_IMPLICIT_RELEASE_DISABLE;
		if (rte_event_port_attr_get(dev_id, i, attr_id, &attr))
			rte_panic("Failed to get port %u's implicit release attr\n",
				  i);

		port_confs[i].event_port_cfg = 0;
		if (attr)
			port_confs[i].event_port_cfg |=
				RTE_EVENT_PORT_CFG_DISABLE_IMPL_REL;
	}

	for (i = 0; i < num_queues; i++) {
		uint32_t attr;

		attr_id = RTE_EVENT_QUEUE_ATTR_NB_ATOMIC_ORDER_SEQUENCES;
		if (rte_event_queue_attr_get(dev_id, i, attr_id, &attr))
			rte_panic("Failed to get queue %u's ordered SN config\n",
				  i);

		queue_confs[i].nb_atomic_order_sequences = attr;

		attr_id = RTE_EVENT_QUEUE_ATTR_EVENT_QUEUE_CFG;
		if (rte_event_queue_attr_get(dev_id, i, attr_id, &attr))
			rte_panic("Failed to get queue %u's queue cfg\n",
				  i);

		queue_confs[i].event_queue_cfg = attr;

		/* This function returns -EOVERFLOW when the queue was
		 * configured with RTE_EVENT_QUEUE_CFG_ALL_TYPES. In that
		 * case, schedule_type is a don't-care value.
		 */
		attr_id = RTE_EVENT_QUEUE_ATTR_SCHEDULE_TYPE;

		ret = rte_event_queue_attr_get(dev_id, i, attr_id, &attr);
		if (ret && ret != -EOVERFLOW)
			rte_panic("Failed to get queue %u's schedule type\n",
				  i);

		queue_confs[i].schedule_type = attr;
	}

	/* Lookup port->queue link information */
	for (i = 0; i < num_ports; i++) {
		ret = rte_event_port_links_get(dev_id, i,
					       port_links[i].queues,
					       port_links[i].priorities);
		if (ret < 0)
			rte_panic("Failed to get port %u's links\n", i);

		port_links[i].num_links = ret;
	}

	for (i = 0; i < num_ports; i++) {
		ret = rte_event_dev_xstats_get(
			dev_id,
			RTE_EVENT_DEV_XSTATS_PORT,
			i,
			&port_xstat_ids[i][PORT_IS_LOAD_BALANCED],
			&port_xstat_vals[i][PORT_IS_LOAD_BALANCED],
			1);
		if (ret != 1)
			rte_panic("Failed to get port %u's is_load_balanced xstat (ret: %d)\n",
				  i, ret);
	}
	ret = rte_event_dev_xstats_get(dev_id,
				       RTE_EVENT_DEV_XSTATS_DEVICE,
				       0,
				       &dev_xstat_ids[DEV_LDB_POOL_SIZE],
				       &dev_xstat_vals[DEV_LDB_POOL_SIZE],
				       1);

	if (ret != 1)
		rte_panic("Failed to get ldb pool size\n");

	ret = rte_event_dev_xstats_get(dev_id,
				       RTE_EVENT_DEV_XSTATS_DEVICE,
				       0,
				       &dev_xstat_ids[DEV_DIR_POOL_SIZE],
				       &dev_xstat_vals[DEV_DIR_POOL_SIZE],
				       1);

	if (ret != 1)
		rte_panic("Failed to get dir pool size\n");

	ret = rte_event_dev_xstats_get(dev_id,
				       RTE_EVENT_DEV_XSTATS_DEVICE,
				       0,
				       &dev_xstat_ids[DEV_POOL_SIZE],
				       &dev_xstat_vals[DEV_POOL_SIZE],
				       1);
	if (ret != 1)
		rte_panic("Failed to get pool size\n");
}

static void
collect_stats(void)
{
	unsigned int i;
	int ret;

	/* Lookup port->queue link information */
	for (i = 0; i < num_ports; i++) {
		ret = rte_event_port_links_get(dev_id, i,
					       port_links[i].queues,
					       port_links[i].priorities);
		if (ret < 0)
			rte_panic("Failed to get port %u's links\n", i);

		port_links[i].num_links = ret;
	}

	/* Wait while the eventdev application executes */
	rte_delay_us_sleep(measure_time_us);

	/* Collect xstats */
	ret = rte_event_dev_xstats_get(dev_id,
				       RTE_EVENT_DEV_XSTATS_DEVICE,
				       0,
				       dev_xstat_ids,
				       dev_xstat_vals,
				       RTE_DIM(dev_xstat_strs));

	if (ret != RTE_DIM(dev_xstat_strs))
		rte_panic("Failed to get device xstats\n");

	for (i = 0; i < num_ports; i++) {
		ret = rte_event_dev_xstats_get(dev_id,
					       RTE_EVENT_DEV_XSTATS_PORT,
					       i,
					       port_xstat_ids[i],
					       port_xstat_vals[i],
					       RTE_DIM(port_xstat_strs));
		if (ret != RTE_DIM(port_xstat_strs))
			rte_panic("Failed to get port %u's xstats (ret: %d)\n",
				  i, ret);
	}

	for (i = 0; i < num_queues; i++) {
		ret = rte_event_dev_xstats_get(dev_id,
					       RTE_EVENT_DEV_XSTATS_QUEUE,
					       i,
					       queue_xstat_ids[i],
					       queue_xstat_vals[i],
					       RTE_DIM(queue_xstat_strs));
		if (ret != RTE_DIM(queue_xstat_strs))
			rte_panic("Failed to get queue %u's xstats\n", i);
	}
}

#define PCT_STR_LEN 5
static void
format_percent_str(float pct, char *str)
{
	if (pct > 0.0f && pct < 1.0f)
		snprintf(str, PCT_STR_LEN, " <1%%");
	else
		snprintf(str, PCT_STR_LEN, "%3.0f%%", pct);
}

#define COL_RED "\x1b[31m"
#define COL_RESET "\x1b[0m"
#define LINK_STR_LEN 11

static void
display_port_config(void)
{
	unsigned int i;

	printf("                                            Port Configuration\n");
	printf("------------------------------------------------------------------------------------------------------------------\n");
	printf("    |      |     |     |  New   |Implicit| Link 0 | Link 1 | Link 2 | Link 3 | Link 4 | Link 5 | Link 6 | Link 7 |\n");
	printf("    |      | Enq | Deq | event  | release|(Queue, |(Queue, |(Queue, |(Queue, |(Queue, |(Queue, |(Queue, |(Queue, |\n");
	printf("Port| Type |Depth|Depth| thresh | enabled|  Prio) |  Prio) |  Prio) |  Prio) |  Prio) |  Prio) |  Prio) |  Prio) |\n");
	printf("----|------|-----|-----|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|\n");

	for (i = 0; i < num_ports; i++) {
		char link_str[MAX_QUEUES_PER_PORT][LINK_STR_LEN] = {
			"        ",
			"        ",
			"        ",
			"        ",
			"        ",
			"        ",
			"        ",
			"        ",
		};
		bool is_ldb, impl_rel_enab;
		int j;

		is_ldb = port_xstat_vals[i][PORT_IS_LOAD_BALANCED];

		for (j = 0; j < port_links[i].num_links; j++) {
			if (port_links[i].queues[j] < 10)
				snprintf(link_str[j], 11, "  Q%1u,P%u ",
					 port_links[i].queues[j],
					 port_links[i].priorities[j] >> 5);
			else if (port_links[i].queues[j] < 100)
				snprintf(link_str[j], 10, " Q%2u,P%u ",
					 port_links[i].queues[j],
					 port_links[i].priorities[j] >> 5);
			else
				snprintf(link_str[j], 10, "Q%3u,P%u ",
					 port_links[i].queues[j],
					 port_links[i].priorities[j] >> 5);
		}

		impl_rel_enab = (port_confs[i].event_port_cfg &
				 RTE_EVENT_PORT_CFG_DISABLE_IMPL_REL) == 0;

		printf("%3u |  %s | %3u | %3u |  %5u |    %u   |%s|%s|%s|%s|%s|%s|%s|%s|\n",
			i, is_ldb ? "LDB" : "DIR",
			port_confs[i].enqueue_depth,
			port_confs[i].dequeue_depth,
			port_confs[i].new_event_threshold,
			impl_rel_enab,
			link_str[0], link_str[1], link_str[2], link_str[3],
			link_str[4], link_str[5], link_str[6], link_str[7]);
	}

	printf("------------------------------------------------------------------------------------------------------------------\n");

	printf("\n");
}

static void
display_queue_config(void)
{
	bool print_ord_sn_warning;
	unsigned int i;

	print_ord_sn_warning = false;

	printf("      Queue Configuration\n");
	printf("-----------------------------------\n");
	printf("     |  Sched  | Ordered sequence |\n");
	printf("Queue|  Types  |      numbers     |\n");
	printf("-----|---------|------------------|\n");

	for (i = 0; i < num_queues; i++) {
		bool is_dir, is_uno, too_few_sns, is_all_types;
		unsigned int j, ord_sns;
		int num_linked_ports;

		is_dir = queue_confs[i].event_queue_cfg &
			RTE_EVENT_QUEUE_CFG_SINGLE_LINK;

		is_uno = false;

		is_all_types = queue_confs[i].event_queue_cfg &
			RTE_EVENT_QUEUE_CFG_ALL_TYPES;

		if (is_all_types &&
		    queue_confs[i].nb_atomic_order_sequences == 0)
			is_uno = true;

		if (!is_all_types &&
		    queue_confs[i].schedule_type != RTE_SCHED_TYPE_ORDERED)
			is_uno = true;

		ord_sns = queue_confs[i].nb_atomic_order_sequences;
		if (is_dir || is_uno)
			ord_sns = 0;

		num_linked_ports = 0;
		for (j = 0; j < num_ports; j++) {
			int k;
			for (k = 0; k < port_links[j].num_links; k++) {
				if (port_links[j].queues[k] == i)
					num_linked_ports++;
			}
		}

		too_few_sns = (ord_sns > 0) &&
			      (num_linked_ports > 0) &&
			      ((ord_sns / num_linked_ports) <= 4);

		print_ord_sn_warning |= too_few_sns;

		printf(" %3u | %s |       %s%4u%s       |\n",
			i,
			is_dir ? "  DIR  " : is_uno ? "ATM+PAR" : "ATM+ORD",
			too_few_sns ? COL_RED : "", ord_sns, COL_RESET);
	}

	printf("-----------------------------------\n");

	if (print_ord_sn_warning)
		printf("\n%sOrdered sequence numbers%s: an ordered queue's nb_atomic_order_sequences sets\n"
		       "			  its inflight event limit: the number of the\n"
		       "			  queue's events that can be scheduled and awaiting\n"
		       "			  release at any time. If this number is too low,\n"
		       "			  it can limit the parallelism of the application.\n"
		       "			  Consider increasing the queue's SN config.\n",
			COL_RED, COL_RESET);
	printf("\n");
}

static void
display_device_config(void)
{
	printf("\n");
	printf("          Device Configuration\n");
	printf("-----------------------------------------------------------\n");
	printf("      |  LDB pool size |  DIR pool size |  COMB pool size |\n");
	printf("Device|    (DLB 2.0)   |    (DLB 2.0)   |     (DLB 2.5)   |\n");
	printf("------|----------------|----------------|-----------------|\n");

	printf("  %2u  |     %5"PRIu64"      |      %4"PRIu64"      |",
		dev_id,
		dev_xstat_vals[DEV_LDB_POOL_SIZE],
		dev_xstat_vals[DEV_DIR_POOL_SIZE]);
	printf("      %5"PRIu64"      |\n",
		dev_xstat_vals[DEV_POOL_SIZE]);
	printf("-----------------------------------------------------------\n");
	printf("\n");
}

static void
display_config(void)
{
	display_device_config();

	display_port_config();

	display_queue_config();
}

/* Load imbalance is detected if, among ports with identical queue links
 * (including priority), the port with the most dequeued events has at least
 * a factor of LOAD_IMBALANCE_THRESHOLD more events than the port with the
 * fewest dequeued events.
 */
#define LOAD_IMBALANCE_THRESHOLD 1.5f

static bool
detect_load_imbalance(unsigned int port_id)
{
	unsigned int i, j, k, num_links;
	uint64_t rx_ok_high, rx_ok_low;

	rx_ok_high = port_xstat_vals[port_id][RX_OK];
	rx_ok_low = port_xstat_vals[port_id][RX_OK];

	num_links = port_links[port_id].num_links;

	for (i = 0; i < num_ports; i++) {
		if (i == port_id)
			continue;

		if (port_links[i].num_links != (int)num_links)
			continue;

		/* Check if ports port_id and i have the same queue links */
		for (j = 0; j < num_links; j++) {
			for (k = 0; k < num_links; k++) {
				if ((port_links[i].queues[j] ==
				     port_links[port_id].queues[k]) &&
				    (port_links[i].priorities[j] ==
				     port_links[port_id].priorities[k]))
					break;
			}

			/* Break early if no match found */
			if (k == num_links)
				break;
		}

		if (j < num_links)
			continue;

		rx_ok_high = RTE_MAX(rx_ok_high, port_xstat_vals[i][RX_OK]);
		rx_ok_low = RTE_MIN(rx_ok_low, port_xstat_vals[i][RX_OK]);
	}

	return rx_ok_low * LOAD_IMBALANCE_THRESHOLD < rx_ok_high;
}

static void
display_device_stats(void)
{
	float ldb_sched_throughput, dir_sched_throughput;
	uint64_t events_inflight, nb_events_limit;
	uint64_t total = 0;
	unsigned int i;

	events_inflight = dev_xstat_vals[DEV_INFL_EVENTS];
	nb_events_limit = dev_xstat_vals[DEV_NB_EVENTS_LIMIT];

	ldb_sched_throughput = 0.0f;
	dir_sched_throughput = 0.0f;

	for (i = 0; i < num_ports; i++) {
		if (port_xstat_vals[i][PORT_IS_LOAD_BALANCED]) {
			ldb_sched_throughput +=
				(port_xstat_vals[i][RX_OK] -
				prev_sched_throughput[i]);
		} else {
			dir_sched_throughput +=
				(port_xstat_vals[i][RX_OK] -
				prev_sched_throughput[i]);
		}

		total += (port_xstat_vals[i][RX_OK] -
				prev_sched_throughput[i]);
		prev_sched_throughput[i] = port_xstat_vals[i][RX_OK];
	}

	/* Throughput is displayed in millions of events per second, so no need
	 * to convert microseconds to seconds.
	 */
	ldb_sched_throughput = ldb_sched_throughput / measure_time_us;
	dir_sched_throughput = dir_sched_throughput / measure_time_us;

	printf("                        Device stats\n");
	printf("-----------------------------------------------------------\n");
	printf("LDB scheduling throughput: %.2f ME/s (%.2f ME/s globally)\n",
	       ldb_sched_throughput,
	       (float)total / (float)measure_time_us);
	printf("DIR scheduling throughput: %.2f ME/s (%.2f ME/s globally)\n",
	       dir_sched_throughput,
	       (float)total / (float)measure_time_us);
	printf("Inflight events: %"PRIu64"/%"PRIu64"\n",
	       events_inflight, nb_events_limit);
	printf("\n");
}

static void
display_port_dequeue_stats(void)
{
	unsigned int i;

	printf("                               Port dequeue stats\n");
	printf("-----------------------------------------------------------------------------\n");
	printf("    |  Sched  |                |  Out-  |   Dequeued sched   |Avg evts| Zero|\n");
	printf("    |throughpt|  Total events  |standing|   type percentage  |  per   | poll|\n");
	printf("Port|  (ME/s) |    dequeued    |Releases| ATM  PAR  ORD  DIR |dequeue |  pct|\n");
	printf("----|---------|----------------|--------|--------------------|--------|-----|\n");

	bool print_load_imbalance_warning = false;
	bool print_batch_size_warning = false;

	for (i = 0; i < num_ports; i++) {
		float sched_tput, atm_pct, par_pct, ord_pct, zero_poll_pct;
		char atm_str[PCT_STR_LEN], par_str[PCT_STR_LEN];
		char ord_str[PCT_STR_LEN], dir_str[PCT_STR_LEN];
		uint64_t rx_ok, total_polls, zero_polls;
		char zero_poll_str[PCT_STR_LEN];
		bool low_batch_size, imbalance;
		float dir_pct, avg_deq_size;

		rx_ok = port_xstat_vals[i][RX_OK];
		total_polls = port_xstat_vals[i][TOTAL_POLLS];
		zero_polls = port_xstat_vals[i][ZERO_POLLS];

		if (skip_zero && rx_ok == 0)
			continue;

		zero_poll_pct = (zero_polls * 100.0f) / total_polls;

		if (total_polls == 0)
			zero_poll_pct = 0.0f;

		format_percent_str(zero_poll_pct, zero_poll_str);

		atm_pct = port_xstat_vals[i][RX_SCHED_ATOMIC];
		atm_pct = (atm_pct * 100.0f) / rx_ok;

		ord_pct = port_xstat_vals[i][RX_SCHED_ORDERED];
		ord_pct = (ord_pct * 100.0f) / rx_ok;

		par_pct = port_xstat_vals[i][RX_SCHED_UNORDERED];
		par_pct = (par_pct * 100.0f) / rx_ok;

		dir_pct = 0.0f;

		if (!port_xstat_vals[i][PORT_IS_LOAD_BALANCED]) {
			atm_pct = 0.0f;
			ord_pct = 0.0f;
			par_pct = 0.0f;
			dir_pct = rx_ok > 0 ? 100.0f : 0.0f;
		}

		if (rx_ok == 0) {
			atm_pct = 0.0f;
			ord_pct = 0.0f;
			par_pct = 0.0f;
			dir_pct = 0.0f;
		}

		format_percent_str(atm_pct, atm_str);
		format_percent_str(ord_pct, ord_str);
		format_percent_str(par_pct, par_str);
		format_percent_str(dir_pct, dir_str);

		avg_deq_size = (float)rx_ok / (float)total_polls;
		if (total_polls == 0)
			avg_deq_size = 0.0f;

		/* Throughput is displayed in millions of events per second, so
		 * no need to convert microseconds to seconds.
		 */
		sched_tput = (float)(port_xstat_vals[i][RX_OK] -
				     prev_sched_throughput[i]) /
				  (float)measure_time_us;

		low_batch_size = false;
		if (avg_deq_size > 0.0f &&
		    avg_deq_size <= port_confs[i].dequeue_depth / 8)
			low_batch_size = true;

		print_batch_size_warning |= low_batch_size;

		imbalance = detect_load_imbalance(i);
		print_load_imbalance_warning |= imbalance;

		printf("%3u |  %6.2f |%s%16"PRIu64"%s| %3"PRIu64"/%-3"PRIu64"|%s %s %s %s | %s%6.2f%s | %s|\n",
			i, sched_tput,
			imbalance ? COL_RED : "", port_xstat_vals[i][RX_OK],
			COL_RESET,
			port_xstat_vals[i][OUTSTANDING_RELEASES],
			port_xstat_vals[i][MAX_OUTSTANDING_RELEASES],
			atm_str, par_str, ord_str, dir_str,
			low_batch_size ? COL_RED : "", avg_deq_size, COL_RESET,
			zero_poll_str);
	}

	printf("-----------------------------------------------------------------------------\n");

	if (print_batch_size_warning)
		printf("\nDequeue batch size: when the average dequeue size is much lower than the port's\n"
		       "		    dequeue depth, likely either dequeue burst is called with a\n"
		       "		    small nb_events argument, or event producers are supplying\n"
		       "		    the port at a slower rate than it can dequeue events.\n");
	if (print_load_imbalance_warning)
		printf("\nLoad imbalance: the total events dequeued by certain ports with identical queue\n"
		       "		links differs by at least %3.1fx. This can be caused by using a\n"
		       "		small number of atomic flows, or if one core is being preempted\n"
		       "		more frequently than another.\n",
		       LOAD_IMBALANCE_THRESHOLD);
	printf("\n");
}

static void
display_port_enqueue_stats(void)
{
	bool print_new_rel_warning = false;
	bool print_ldb_deadlock = false;
	bool print_dir_deadlock = false;
	bool print_comb_deadlock = false;
	bool print_ldb = false;
	bool print_dir = false;
	bool print_comb = false;
	bool print_net = false;
	bool print_inf = false;
	bool print_swc = false;
	unsigned int i;

	printf("                                 Port enqueue stats\n");
	printf("-----------------------------------------------------------------------------------------------\n");
	printf("    |                |   Enqueued sched   |     Enqueued op    |    %% of enqueue attempts     |\n");
	printf("    |  Total events  |   type percentage  |   type percentage  |          backpressured       |\n");
	printf("Port|    enqueued    | ATM  PAR  ORD  DIR | NEW  FWD  REL      | LDB  DIR  COMB NET  INF  SWC |\n");
	printf("----|----------------|--------------------|--------------------|------------------------------|\n");

	for (i = 0; i < num_ports; i++) {
		char ldb_bp_str[PCT_STR_LEN], dir_bp_str[PCT_STR_LEN];
		char comb_bp_str[PCT_STR_LEN];
		char net_bp_str[PCT_STR_LEN], inf_bp_str[PCT_STR_LEN];
		char new_str[PCT_STR_LEN], fwd_str[PCT_STR_LEN];
		char rel_str[PCT_STR_LEN];
		char atm_str[PCT_STR_LEN], par_str[PCT_STR_LEN];
		char ord_str[PCT_STR_LEN], dir_str[PCT_STR_LEN];
		float ldb_bp_pct, dir_bp_pct, comb_bp_pct, net_bp_pct;
		float atm_pct, par_pct, ord_pct, dir_pct;
		float new_pct, fwd_pct, rel_pct;
		float inf_bp_pct, swc_bp_pct;
		char swc_bp_str[PCT_STR_LEN];
		uint64_t tx_ok, total_tx;
		bool new_rel_issue;

		tx_ok = port_xstat_vals[i][TX_OK];

		if (skip_zero && tx_ok == 0)
			continue;

		atm_pct = port_xstat_vals[i][TX_SCHED_ATOMIC];
		atm_pct = (atm_pct * 100.0f) / tx_ok;

		ord_pct = port_xstat_vals[i][TX_SCHED_ORDERED];
		ord_pct = (ord_pct * 100.0f) / tx_ok;

		par_pct = port_xstat_vals[i][TX_SCHED_UNORDERED];
		par_pct = (par_pct * 100.0f) / tx_ok;

		dir_pct = port_xstat_vals[i][TX_SCHED_DIRECTED];
		dir_pct = (dir_pct * 100.0f) / tx_ok;

		new_pct = port_xstat_vals[i][TX_NEW];
		new_pct = (new_pct * 100.0f) / tx_ok;

		fwd_pct = port_xstat_vals[i][TX_FWD];
		fwd_pct = (fwd_pct * 100.0f) / tx_ok;

		rel_pct = port_xstat_vals[i][TX_REL];
		rel_pct = (rel_pct * 100.0f) / tx_ok;

		if (tx_ok == 0) {
			atm_pct = 0.0f;
			ord_pct = 0.0f;
			par_pct = 0.0f;
			dir_pct = 0.0f;
			new_pct = 0.0f;
			fwd_pct = 0.0f;
			rel_pct = 0.0f;
		}

		format_percent_str(atm_pct, atm_str);
		format_percent_str(ord_pct, ord_str);
		format_percent_str(par_pct, par_str);
		format_percent_str(dir_pct, dir_str);
		format_percent_str(new_pct, new_str);
		format_percent_str(fwd_pct, fwd_str);
		format_percent_str(rel_pct, rel_str);

		new_rel_issue = new_pct >= 40.0f && rel_pct >= 40.0f;

		print_new_rel_warning |= new_rel_issue;

		total_tx = port_xstat_vals[i][TX_NOSPC_LDB_HW_CREDITS] +
			port_xstat_vals[i][TX_NOSPC_DIR_HW_CREDITS] +
			port_xstat_vals[i][TX_NOSPC_HW_CREDITS] +
			port_xstat_vals[i][TX_NOSPC_INFL_MAX] +
			port_xstat_vals[i][TX_NOSPC_NEW_EVENT_LIM] +
			port_xstat_vals[i][TX_NOSPC_INFL_CREDITS] +
			tx_ok;

		ldb_bp_pct = port_xstat_vals[i][TX_NOSPC_LDB_HW_CREDITS];
		ldb_bp_pct = (ldb_bp_pct * 100.0f) / total_tx;

		dir_bp_pct = port_xstat_vals[i][TX_NOSPC_DIR_HW_CREDITS];
		dir_bp_pct = (dir_bp_pct * 100.0f) / total_tx;

		comb_bp_pct = port_xstat_vals[i][TX_NOSPC_HW_CREDITS];
		comb_bp_pct = (comb_bp_pct * 100.0f) / total_tx;

		net_bp_pct = port_xstat_vals[i][TX_NOSPC_INFL_MAX];
		net_bp_pct = (net_bp_pct * 100.0f) / total_tx;

		inf_bp_pct = port_xstat_vals[i][TX_NOSPC_NEW_EVENT_LIM];
		inf_bp_pct = (inf_bp_pct * 100.0f) / total_tx;

		swc_bp_pct = port_xstat_vals[i][TX_NOSPC_INFL_CREDITS];
		swc_bp_pct = (swc_bp_pct * 100.0f) / total_tx;

		if (total_tx == 0) {
			ldb_bp_pct = 0.0f;
			dir_bp_pct = 0.0f;
			comb_bp_pct = 0.0f;
			net_bp_pct = 0.0f;
			inf_bp_pct = 0.0f;
			swc_bp_pct = 0.0f;
		}

		print_ldb_deadlock |= ldb_bp_pct > 90.0f;
		print_dir_deadlock |= dir_bp_pct > 90.0f;
		print_comb_deadlock |= comb_bp_pct > 90.0f;
		print_ldb |= ldb_bp_pct > 0.0f;
		print_dir |= dir_bp_pct > 0.0f;
		print_comb |= comb_bp_pct > 0.0f;
		print_net |= net_bp_pct > 0.0f;
		print_inf |= inf_bp_pct > 0.0f;
		print_swc |= swc_bp_pct > 0.0f;

		format_percent_str(ldb_bp_pct, ldb_bp_str);
		format_percent_str(dir_bp_pct, dir_bp_str);
		format_percent_str(comb_bp_pct, comb_bp_str);
		format_percent_str(net_bp_pct, net_bp_str);
		format_percent_str(inf_bp_pct, inf_bp_str);
		format_percent_str(swc_bp_pct, swc_bp_str);

		printf("%3u |%16"PRIu64"|%s %s %s %s |%s%s%s %s %s%s%s      |%s %s %s %s%s%s %s %s |\n",
			i,
			tx_ok,
			atm_str, par_str, ord_str, dir_str,
			new_rel_issue ? COL_RED : "", new_str, COL_RESET,
			fwd_str,
			new_rel_issue ? COL_RED : "", rel_str, COL_RESET,
			ldb_bp_str,
			dir_bp_str,
			comb_bp_str,
			net_bp_pct > 25.0f ? COL_RED : "", net_bp_str,
			COL_RESET,
			inf_bp_str,
			swc_bp_str);
	}

	printf("-----------------------------------------------------------------------------------------------\n");

	if (print_ldb)
		printf("\nLDB backpressure: insufficient load-balanced hardware credits. Can occur\n"
		       "                  occasionally when enqueueing faster than DLB refills credits.\n");
	if (print_ldb_deadlock)
		printf("\n                  A high LDB%% may be caused by credit deadlock. Threads should\n"
		       "                  retry enqueue with a retry limit, and drop any unsent events\n"
		       "                  if the limit is reached to release credits.\n");
	if (print_dir)
		printf("\nDIR backpressure: insufficient directed hardware credits. Can occur\n"
		       "                  occasionally when enqueueing faster than DLB refills credits.\n");
	if (print_dir_deadlock)
		printf("\n                  A high DIR%% may be caused by credit deadlock. Threads should\n"
		       "                  retry enqueue with a retry limit, and drop any unsent events\n"
		       "                  if the limit is reached to release credits.\n");
	if (print_comb)
		printf("\nCOMB backpressure: insufficient hardware credits. Can occur\n"
		       "                  occasionally when enqueueing faster than DLB refills credits.\n");
	if (print_comb_deadlock)
		printf("\n                  A high COMB%% may be caused by credit deadlock. Threads should\n"
		       "                  retry enqueue with a retry limit, and drop any unsent events\n"
		       "                  if the limit is reached to release credits.\n");
	if (print_net)
		printf("\nNET backpressure: unable to enqueue NEW events because inflight events exceeded\n"
		       "                  the port's New Event Threshold. Indicates the events are being\n"
		       "                  processed and released slower than the enqueue rate.\n");
	if (print_inf)
		printf("\nINF backpressure: unable to enqueue because device-maximum events are inflight.\n");
	if (print_swc)
		printf("\nSWC backpressure: insufficient software credits.\n");
	if (print_new_rel_warning)
		printf("\n%sNEW + REL vs FWD%s: It is more efficient to send a FORWARD event vs. a NEW event\n"
		       "                  followed by a RELEASE event. Unless you are intentionally\n"
		       "		  releasing events early, FORWARD events are strongly recommended.\n",
		       COL_RED, COL_RESET);
	printf("\n");
}

static void
display_queue_stats(void)
{
	float total_queue_depth_pct = 0.0f;
	bool print_queue_warning = false;
	int queue_warning_id = 0;
	unsigned int i;

	printf("                                  Queue stats\n");
	printf("-------------------------------------------------------------------------------\n");
	printf("Queue|Type|Depth|                        Depth (%%)                            |\n");
	printf("-----|----|-----|-------------------------------------------------------------|\n");

#define MAX_DEPTH_STRING_LEN 62
	for (i = 0; i < num_queues; i++) {
		uint64_t depth, max_depth, depth_pct;
		char str[MAX_DEPTH_STRING_LEN + 1];
		bool is_ldb, high_queue_depth;
		int j;

		is_ldb = queue_xstat_vals[i][QUEUE_IS_LOAD_BALANCED];

		max_depth = is_ldb ? dev_xstat_vals[DEV_LDB_POOL_SIZE] :
				     dev_xstat_vals[DEV_DIR_POOL_SIZE];

		depth = queue_xstat_vals[i][CURRENT_DEPTH];

		if (max_depth == 0) {  /* DLB 2.5 uses combined credit pool */
			max_depth = dev_xstat_vals[DEV_POOL_SIZE];
			depth = queue_xstat_vals[i][CURRENT_DEPTH];
		}

		if (skip_zero && depth == 0)
			continue;

		/* Normalize depth_pct to MAX_DEPTH_STRING_LEN */
		depth_pct = (MAX_DEPTH_STRING_LEN * depth) / max_depth;
		total_queue_depth_pct += (100.0f * depth) / max_depth;

		high_queue_depth = false;

		/* Flag the queue's depth if it is using at least 50% of the
		 * available credits.
		 */
		if (((100.0f * depth) / max_depth) >= 50.0f) {
			high_queue_depth = true;
			queue_warning_id = i;
		}

		print_queue_warning |= high_queue_depth;

		/* (max depth string len - 1: reserve one entry for the '>') */
		for (j = 0; j < MAX_DEPTH_STRING_LEN - 1; j++) {
			if (depth_pct > 0 && (unsigned int)j <= depth_pct - 1)
				str[j] = '=';
			else
				str[j] = ' ';
		}

		if ((depth_pct > 0 || depth > 0) &&
		    (depth_pct < MAX_DEPTH_STRING_LEN))
			str[depth_pct] = '>';

		str[MAX_DEPTH_STRING_LEN] = '\0';

		printf(" %3u |%s|%s%5"PRIu64"%s|%s%s%s|\n",
		       i,
		       is_ldb ? " LDB" : " DIR",
		       high_queue_depth ? COL_RED : "", depth, COL_RESET,
		       high_queue_depth ? COL_RED : "", str, COL_RESET);
	}

	printf("-------------------------------------------------------------------------------\n");
        if (dev_xstat_vals[DEV_POOL_SIZE] > 8192) /* DIR enqueue depth MSB is not accessible */
        {
                printf("WARNING: DIR Depth only shows lower 12 bits. \n If current depth is > 8192, displayed value will be incorrect\n");
	printf("-------------------------------------------------------------------------------\n");
        }

	if (total_queue_depth_pct < 10.0f)
		printf("\nLow queue depth: the queues are under-utilized, likely caused by a low event injection rate.\n");
	if (print_queue_warning)
		printf("\nHigh queue depth: queue %u's depth is very high. The port(s) servicing it are\n"
		       "                  likely processing slower than the event enqueue rate.\n",
		       queue_warning_id);

	printf("\n");
}

static void
display_stats(void)
{
	display_port_dequeue_stats();

	display_port_enqueue_stats();

	display_queue_stats();

	display_device_stats();

	printf("Note: scheduling throughput measured over a duration of %us. All other stats are instantaneous samples.\n",
	       measure_time_us / US_PER_S);
	printf("\n");
}

int
main(int argc, char **argv)
{
	int i, diag, cnt;
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
		rte_panic("Cannot init EAL\n");

	argc -= diag;
	argv += (diag - 3);

	/* Parse cli options*/
	parse_app_args(argc, argv);

	const uint8_t ndevs = rte_event_dev_count();
	if (ndevs == 0)
		rte_panic("No event devs found. Missing --vdev flag?\n");
	if (ndevs <= dev_id)
		rte_panic("Invalid eventdev ID %d (%d devices available)\n",
			  dev_id, ndevs);

	printf("\n");

	/* Get and output any stats requested on the command line */
	collect_config();

	display_config();

	cnt = 0;

	do {
		collect_stats();

		if (do_watch)
			printf("Sample #%d\n", cnt++);

		if (skip_zero)
			printf("Skipping ports and queues with zero stats\n");

		display_stats();

		if (do_reset) {
			rte_event_dev_xstats_reset(dev_id,
						   RTE_EVENT_DEV_XSTATS_DEVICE,
						   -1, NULL, 0);
			rte_event_dev_xstats_reset(dev_id,
						   RTE_EVENT_DEV_XSTATS_PORT,
						   -1, NULL, 0);
			rte_event_dev_xstats_reset(dev_id,
						   RTE_EVENT_DEV_XSTATS_QUEUE,
						   -1, NULL, 0);
			for (i = 0; i < MAX_PORTS_QUEUES; i++)
				prev_sched_throughput[i] = 0;
		}
	} while (do_watch);

	return 0;
}
