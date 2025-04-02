/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 */

#include <math.h>

#include "test_perf_common.h"

#define NB_CRYPTODEV_DESCRIPTORS 1024
#define DATA_SIZE		512
struct modex_test_data {
	enum rte_crypto_asym_xform_type xform_type;
	struct {
		uint8_t data[DATA_SIZE];
		uint16_t len;
	} base;
	struct {
		uint8_t data[DATA_SIZE];
		uint16_t len;
	} exponent;
	struct {
		uint8_t data[DATA_SIZE];
		uint16_t len;
	} modulus;
	struct {
		uint8_t data[DATA_SIZE];
		uint16_t len;
	} reminder;
	uint16_t result_len;
};

static struct
modex_test_data modex_test_case = {
	.xform_type = RTE_CRYPTO_ASYM_XFORM_MODEX,
	.base = {
		.data = {
			0xF8, 0xBA, 0x1A, 0x55, 0xD0, 0x2F, 0x85,
			0xAE, 0x96, 0x7B, 0xB6, 0x2F, 0xB6, 0xCD,
			0xA8, 0xEB, 0x7E, 0x78, 0xA0, 0x50
		},
		.len = 20,
	},
	.exponent = {
		.data = {
			0x01, 0x00, 0x01
		},
		.len = 3,
	},
	.reminder = {
		.data = {
			0x2C, 0x60, 0x75, 0x45, 0x98, 0x9D, 0xE0, 0x72,
			0xA0, 0x9D, 0x3A, 0x9E, 0x03, 0x38, 0x73, 0x3C,
			0x31, 0x83, 0x04, 0xFE, 0x75, 0x43, 0xE6, 0x17,
			0x5C, 0x01, 0x29, 0x51, 0x69, 0x33, 0x62, 0x2D,
			0x78, 0xBE, 0xAE, 0xC4, 0xBC, 0xDE, 0x7E, 0x2C,
			0x77, 0x84, 0xF2, 0xC5, 0x14, 0xB5, 0x2F, 0xF7,
			0xC5, 0x94, 0xEF, 0x86, 0x75, 0x75, 0xB5, 0x11,
			0xE5, 0x0E, 0x0A, 0x29, 0x76, 0xE2, 0xEA, 0x32,
			0x0E, 0x43, 0x77, 0x7E, 0x2C, 0x27, 0xAC, 0x3B,
			0x86, 0xA5, 0xDB, 0xC9, 0x48, 0x40, 0xE8, 0x99,
			0x9A, 0x0A, 0x3D, 0xD6, 0x74, 0xFA, 0x2E, 0x2E,
			0x5B, 0xAF, 0x8C, 0x99, 0x44, 0x2A, 0x67, 0x38,
			0x27, 0x41, 0x59, 0x9D, 0xB8, 0x51, 0xC9, 0xF7,
			0x43, 0x61, 0x31, 0x6E, 0xF1, 0x25, 0x38, 0x7F,
			0xAE, 0xC6, 0xD0, 0xBB, 0x29, 0x76, 0x3F, 0x46,
			0x2E, 0x1B, 0xE4, 0x67, 0x71, 0xE3, 0x87, 0x5A
		},
		.len = 128,
	},
	.modulus = {
		.data = {
			0xb3, 0xa1, 0xaf, 0xb7, 0x13, 0x08, 0x00, 0x0a,
			0x35, 0xdc, 0x2b, 0x20, 0x8d, 0xa1, 0xb5, 0xce,
			0x47, 0x8a, 0xc3, 0x80, 0xf4, 0x7d, 0x4a, 0xa2,
			0x62, 0xfd, 0x61, 0x7f, 0xb5, 0xa8, 0xde, 0x0a,
			0x17, 0x97, 0xa0, 0xbf, 0xdf, 0x56, 0x5a, 0x3d,
			0x51, 0x56, 0x4f, 0x70, 0x70, 0x3f, 0x63, 0x6a,
			0x44, 0x5b, 0xad, 0x84, 0x0d, 0x3f, 0x27, 0x6e,
			0x3b, 0x34, 0x91, 0x60, 0x14, 0xb9, 0xaa, 0x72,
			0xfd, 0xa3, 0x64, 0xd2, 0x03, 0xa7, 0x53, 0x87,
			0x9e, 0x88, 0x0b, 0xc1, 0x14, 0x93, 0x1a, 0x62,
			0xff, 0xb1, 0x5d, 0x74, 0xcd, 0x59, 0x63, 0x18,
			0x11, 0x3d, 0x4f, 0xba, 0x75, 0xd4, 0x33, 0x4e,
			0x23, 0x6b, 0x7b, 0x57, 0x44, 0xe1, 0xd3, 0x03,
			0x13, 0xa6, 0xf0, 0x8b, 0x60, 0xb0, 0x9e, 0xee,
			0x75, 0x08, 0x9d, 0x71, 0x63, 0x13, 0xcb, 0xa6,
			0x81, 0x92, 0x14, 0x03, 0x22, 0x2d, 0xde, 0x55
		},
		.len = 128,
	},
	.result_len = 128,
};


#define MAX_PORTS_QUEUES 256
/** Number of elements in the array. */
#define	RTE_DIM(a)	(sizeof (a) / sizeof ((a)[0]))
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

struct MyParams {
    struct prod_data * producer;
    struct worker_data * worker;
};

int
perf_test_result(struct evt_test *test, struct evt_options *opt)
{
	RTE_SET_USED(opt);
	int i;
	uint64_t total = 0;
	struct test_perf *t = evt_test_priv(test);

	printf("Packet distribution across worker cores :\n");
	for (i = 0; i < t->nb_workers; i++)
		total += t->worker[i].processed_pkts;
	for (i = 0; i < t->nb_workers; i++)
		printf("Worker %d packets: "CLGRN"%"PRIx64" "CLNRM"percentage:"
				CLGRN" %3.2f"CLNRM"\n", i,
				t->worker[i].processed_pkts,
				(((double)t->worker[i].processed_pkts)/total)
				* 100);

	return t->result;
}

static inline int
perf_producer(void *arg)
{
	int i;
	struct prod_data *p  = arg;
	struct test_perf *t = p->t;
	struct evt_options *opt = t->opt;
	const uint8_t dev_id = p->dev_id;
	const uint8_t port = p->port_id;
	struct rte_mempool *pool = t->pool;
	const uint64_t nb_pkts = t->nb_pkts;
	const uint32_t nb_flows = t->nb_flows;
	uint32_t flow_counter = 0;
	uint64_t count = 0;
	struct perf_elt *m[BURST_SIZE + 1] = {NULL};
	struct rte_event ev;

	if (opt->verbose_level > 1)
		printf("%s(): lcore %d dev_id %d port=%d queue %d\n", __func__,
				rte_lcore_id(), dev_id, port, p->queue_id);

	ev.event = 0;
	ev.op = RTE_EVENT_OP_NEW;
	ev.queue_id = p->queue_id;
	ev.sched_type = t->opt->sched_type_list[0];
	ev.priority = RTE_EVENT_DEV_PRIORITY_NORMAL;
	ev.event_type =  RTE_EVENT_TYPE_CPU;
	ev.sub_event_type = 0; /* stage 0 */

	while (count < nb_pkts && t->done == false) {
		if (rte_mempool_get_bulk(pool, (void **)m, BURST_SIZE) < 0)
			continue;
		for (i = 0; i < BURST_SIZE; i++) {
			ev.flow_id = flow_counter++ % nb_flows;
			ev.event_ptr = m[i];
			m[i]->timestamp = rte_get_timer_cycles();
            // printf("mbuf pointer is %lu\n", m[i]);
			while (rte_event_enqueue_burst(dev_id,
						       port, &ev, 1) != 1) {
				if (t->done)
					break;
				rte_pause();
				m[i]->timestamp = rte_get_timer_cycles();
			}
		}
		count += BURST_SIZE;
	}

	return 0;
}

static inline int
perf_producer_burst(void *arg)
{
	uint32_t i;
	uint64_t timestamp;
	struct rte_event_dev_info dev_info;
	struct prod_data *p  = arg;
	struct test_perf *t = p->t;
	struct evt_options *opt = t->opt;
	const uint8_t dev_id = p->dev_id;
	const uint8_t port = p->port_id;
	struct rte_mempool *pool = t->pool;
	const uint64_t nb_pkts = t->nb_pkts;
	const uint32_t nb_flows = t->nb_flows;
	uint32_t flow_counter = 0;
	uint16_t enq = 0;
	uint64_t count = 0;
	struct perf_elt *m[MAX_PROD_ENQ_BURST_SIZE + 1] = {NULL};
	struct rte_event ev[MAX_PROD_ENQ_BURST_SIZE + 1];
	uint32_t burst_size = opt->prod_enq_burst_sz;

	rte_event_dev_info_get(dev_id, &dev_info);
	if (dev_info.max_event_port_enqueue_depth < burst_size)
		burst_size = dev_info.max_event_port_enqueue_depth;

	printf("Max enqueue burst size is %d\n", dev_info.max_event_port_enqueue_depth);

	if (opt->verbose_level > 1)
		printf("%s(): lcore %d dev_id %d port=%d queue %d\n", __func__,
				rte_lcore_id(), dev_id, port, p->queue_id);

	for (i = 0; i < burst_size; i++) {
		ev[i].op = RTE_EVENT_OP_NEW;
		ev[i].queue_id = p->queue_id;
		ev[i].sched_type = t->opt->sched_type_list[0];
		ev[i].priority = RTE_EVENT_DEV_PRIORITY_NORMAL;
		ev[i].event_type =  RTE_EVENT_TYPE_CPU;
		ev[i].sub_event_type = 0; /* stage 0 */
	}

	// ==== calculate enqueue rate
	uint64_t hz = rte_get_timer_hz();
    uint64_t prev_tsc, cur_tsc, diff_tsc;
    prev_tsc = rte_get_timer_cycles();
	// ==== calculate enqueue rate

	while (count < nb_pkts && t->done == false) {
		if (rte_mempool_get_bulk(pool, (void **)m, burst_size) < 0)
			continue;
		timestamp = rte_get_timer_cycles();
		for (i = 0; i < burst_size; i++) {
			ev[i].flow_id = flow_counter++ % nb_flows;
			ev[i].event_ptr = m[i];
			m[i]->timestamp = timestamp;
		}
        enq = rte_event_enqueue_burst(dev_id, port, ev, burst_size);
        while (enq < burst_size) {
            enq += rte_event_enqueue_burst(dev_id, port,
                    ev + enq,
                    burst_size - enq);
            if (t->done)
                    break;
			rte_pause();
			timestamp = rte_get_timer_cycles();
			for (i = enq; i < burst_size; i++)
				m[i]->timestamp = timestamp;
        }
		count += burst_size;
	}

	// ==== calculate enqueue rate
	cur_tsc = rte_get_timer_cycles();
	diff_tsc = cur_tsc - prev_tsc;
	double pkt_rate  = (double) count / diff_tsc * hz / 1000000.0;
	printf("\033[1;33m%s(): lcore %d dev_id %d port=%d queue %d, producer pkt_rate is %lf\033[0m\n", __func__,
				rte_lcore_id(), dev_id, port, p->queue_id, pkt_rate);
	// ==== calculate enqueue rate

	return 0;
}


// static inline int
// perf_lat_producer_worker_burst(void * arg)
// {
// 	uint32_t i;

//     // initialization for producer
//     struct MyParams * arg_ptr = arg;
// 	uint64_t timestamp;
// 	struct rte_event_dev_info dev_info;
// 	struct prod_data *p  = arg_ptr->producer;
// 	const uint8_t enq_port = p->port_id;

// 	struct test_perf *t = p->t;
// 	struct evt_options *opt = t->opt;
// 	const uint8_t dev_id = p->dev_id;
// 	struct rte_mempool *pool = t->pool;
// 	const uint64_t nb_pkts = t->nb_pkts;
// 	const uint32_t nb_flows = t->nb_flows;

// 	uint32_t flow_counter = 0;
// 	uint16_t enq = 0;
// 	uint64_t count = 0;
// 	struct perf_elt *m[MAX_PROD_ENQ_BURST_SIZE + 1] = {NULL};
// 	struct rte_event enq_ev[MAX_PROD_ENQ_BURST_SIZE + 1];
// 	uint32_t burst_size = opt->prod_enq_burst_sz;

// 	rte_event_dev_info_get(dev_id, &dev_info);
// 	if (dev_info.max_event_port_enqueue_depth < burst_size)
// 		burst_size = dev_info.max_event_port_enqueue_depth;

// 	// printf("Max enqueue burst size is %d\n", dev_info.max_event_port_enqueue_depth);

// 	if (opt->verbose_level > 1)
// 		printf("%s(): lcore %d dev_id %d enq_port=%d queue %d\n", __func__,
// 				rte_lcore_id(), dev_id, enq_port, p->queue_id);

// 	for (i = 0; i < burst_size; i++) {
// 		enq_ev[i].op = RTE_EVENT_OP_NEW;
// 		enq_ev[i].queue_id = p->queue_id;
// 		enq_ev[i].sched_type = t->opt->sched_type_list[0];
// 		enq_ev[i].priority = RTE_EVENT_DEV_PRIORITY_NORMAL;
// 		enq_ev[i].event_type =  RTE_EVENT_TYPE_CPU;
// 		enq_ev[i].sub_event_type = 0; /* stage 0 */
// 	}

//     // ==== calculate enqueue rate
// 	uint64_t hz = rte_get_timer_hz();
//     uint64_t prev_tsc, cur_tsc, diff_tsc;
//     prev_tsc = rte_get_timer_cycles();
// 	// ==== calculate enqueue rate
    
    
//     // initialization for worker
//     struct rte_event deq_ev[BURST_SIZE + 1];
// 	uint8_t stage;

//     struct worker_data *w  = arg_ptr->worker;
// 	const uint8_t dev = w->dev_id;
// 	const uint8_t deq_port = w->port_id;
// 	const uint8_t prod_timer_type = opt->prod_type == EVT_PROD_TYPE_EVENT_TIMER_ADPTR;
// 	const uint8_t prod_crypto_type = opt->prod_type == EVT_PROD_TYPE_EVENT_CRYPTO_ADPTR;
// 	uint8_t *const sched_type_list = &t->sched_type_list[0];
// 	const uint8_t nb_stages = t->opt->nb_stages;
// 	const uint8_t laststage = nb_stages - 1;
// 	uint8_t cnt = 0;
// 	void *bufs[16] __rte_cache_aligned;
// 	int const sz = RTE_DIM(bufs);
// 	if (opt->verbose_level > 1)
// 		printf("%s(): lcore %d dev_id %d deq_port=%d\n", __func__, rte_lcore_id(), dev, deq_port);

//     /* Time */
//     // MODIFY HERE: TEST LATENCY PERIOD
//     uint16_t interval = 1;  // unit of s
//     uint64_t interval_cycles = (uint64_t) (interval * hz / 1000.0);
//     uint64_t rx_cur_tsc;
// 	uint16_t nb_rx = 0;
//     uint16_t nb_tx = 0;
//     uint64_t c2c_lat;
//     struct perf_elt * ev_ptr_temp;
//     evt_log("Tx queue is %d. nb_stages is %d, last stage is %d.", rte_lcore_id()%evt_nr_active_lcores(opt->wlcores), nb_stages, laststage);


//     // start main program
// 	while (count < nb_pkts && t->done == false) {
//         // enqueue events
// 		if (rte_mempool_get_bulk(pool, (void **)m, burst_size) >= 0) {
//             timestamp = rte_get_timer_cycles();
//             for (i = 0; i < burst_size; i++) {
//                 enq_ev[i].flow_id = flow_counter++ % nb_flows;
//                 enq_ev[i].event_ptr = m[i];
//                 m[i]->timestamp = timestamp;
//             }
//             enq = rte_event_enqueue_burst(dev_id, enq_port, enq_ev, burst_size);
//             while (enq < burst_size) {
//                 enq += rte_event_enqueue_burst(dev_id, enq_port,
//                         enq_ev + enq,
//                         burst_size - enq);
//                 if (t->done)
//                         break;
//                 rte_pause();
//                 timestamp = rte_get_timer_cycles();
//                 for (i = enq; i < burst_size; i++)
//                     m[i]->timestamp = timestamp;
//             }
//             count += burst_size;
//         }

//         rte_pause();

//         // dequeue events
//         nb_rx = rte_event_dequeue_burst(dev, deq_port, deq_ev, BURST_SIZE, 0);
//         if (!nb_rx) {
//             rte_pause();
// 			continue;
// 		} else {
//             rx_cur_tsc = rte_get_timer_cycles();
//             for (i = 0; i < nb_rx; i++) {
//                 stage = deq_ev[i].queue_id % nb_stages;

//                 // latency stats
//                 ev_ptr_temp = deq_ev[i].event_ptr;
//                 c2c_lat = rx_cur_tsc - ev_ptr_temp->timestamp;
//                 c2c_latency_array[(int)rte_lcore_id()][(int)deq_ev[i].queue_id] += c2c_lat;
                

//                 /* last stage in pipeline */
//                 if (unlikely(stage == laststage)) {
//                     cnt = perf_process_last_stage(pool, prod_crypto_type, &deq_ev[i], w, bufs, sz, cnt);
//                     deq_ev[i].op = RTE_EVENT_OP_RELEASE;
//                 } else {
//                     // fwd_event(&ev[i], sched_type_list, nb_stages);
//                 }

//                 // STATS TRACKING
//                 wlcore_queue_pkts[(int)rte_lcore_id()][(int)deq_ev[i].queue_id] += 1;
//                 // printf("%ld, wlcore %d processed packets from queue %d\n", wlcore_queue_pkts[dev][ev[i].queue_id], dev, ev[i].queue_id);
//             }
//         }

// 	}

// 	// ==== calculate enqueue rate
// 	cur_tsc = rte_get_timer_cycles();
// 	diff_tsc = cur_tsc - prev_tsc;
// 	double pkt_rate  = (double) count / diff_tsc * hz / 1000000.0;
// 	printf("\033[1;33m%s(): lcore %d dev_id %d enq_port=%d queue %d, producer pkt_rate is %lf\033[0m\n", __func__,
// 				rte_lcore_id(), dev_id, enq_port, p->queue_id, pkt_rate);
// 	// ==== calculate enqueue rate


//     // // =========== PRINT WORKER STATS
// 	int stats_nb_queues = 0;
// 	uint8_t nb_prod = opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR ?
// 		opt->nb_rx_adapters : evt_nr_active_lcores(opt->plcores);
// 	if (opt->nb_dir_queues)
// 		stats_nb_queues = nb_prod * (opt->nb_stages + 1);
// 	else
// 		stats_nb_queues = nb_prod * opt->nb_stages;

//     // ==== calculate dequeue rate
// 	cur_tsc = rte_get_timer_cycles();
// 	diff_tsc = cur_tsc - prev_tsc;
//     count = 0;
//     uint64_t total_lat = 0;
//     for (uint8_t i = 0; i < stats_nb_queues; i++) {
//         count += wlcore_queue_pkts[rte_lcore_id()][i];
//         total_lat += c2c_latency_array[rte_lcore_id()][i];
// 	}
//     pkt_rate  = (double) count / diff_tsc * hz / 1000000.0;
// 	printf("\033[1;36mwlcore %d dequeue pkt_rate is %lf\033[0m\n", rte_lcore_id(), pkt_rate);
	
//     // ==== calculate core to core latency
//     double avg_lat = (double) total_lat / hz * 1000000.0 / count;
// 	printf("\033[1;36mwlcore %d: total latency is %lu, average core to core latency is %lf\033[0m\n", rte_lcore_id(), total_lat, avg_lat);

// 	// printf("====== Worker %d ======\n", rte_lcore_id());
// 	// for (uint8_t i = 0; i < stats_nb_queues; i++) {
// 	// 	printf("\033[1;36mwlcore %d processed %ld packets (%lf %%) from queue %d\033[0m\n", rte_lcore_id(), wlcore_queue_pkts[rte_lcore_id()][i], wlcore_queue_pkts[rte_lcore_id()][i]*1.0/count*100.0, i);
// 	// }
// 	// =========== PRINT WORKER STATS

// 	perf_worker_cleanup(pool, dev, deq_port, deq_ev, 0, nb_rx);


// 	return 0;
// }


static inline int
perf_event_timer_producer(void *arg)
{
	int i;
	struct prod_data *p  = arg;
	struct test_perf *t = p->t;
	struct evt_options *opt = t->opt;
	uint32_t flow_counter = 0;
	uint64_t count = 0;
	uint64_t arm_latency = 0;
	const uint8_t nb_timer_adptrs = opt->nb_timer_adptrs;
	const uint32_t nb_flows = t->nb_flows;
	const uint64_t nb_timers = opt->nb_timers;
	struct rte_mempool *pool = t->pool;
	struct perf_elt *m[BURST_SIZE + 1] = {NULL};
	struct rte_event_timer_adapter **adptr = t->timer_adptr;
	struct rte_event_timer tim;
	uint64_t timeout_ticks = opt->expiry_nsec / opt->timer_tick_nsec;

	memset(&tim, 0, sizeof(struct rte_event_timer));
	timeout_ticks =
		opt->optm_timer_tick_nsec
			? ceil((double)(timeout_ticks * opt->timer_tick_nsec) /
			       opt->optm_timer_tick_nsec)
			: timeout_ticks;
	timeout_ticks += timeout_ticks ? 0 : 1;
	tim.ev.event_type = RTE_EVENT_TYPE_TIMER;
	tim.ev.op = RTE_EVENT_OP_NEW;
	tim.ev.sched_type = t->opt->sched_type_list[0];
	tim.ev.queue_id = p->queue_id;
	tim.ev.priority = RTE_EVENT_DEV_PRIORITY_NORMAL;
	tim.state = RTE_EVENT_TIMER_NOT_ARMED;
	tim.timeout_ticks = timeout_ticks;

	if (opt->verbose_level > 1)
		printf("%s(): lcore %d\n", __func__, rte_lcore_id());

	while (count < nb_timers && t->done == false) {
		if (rte_mempool_get_bulk(pool, (void **)m, BURST_SIZE) < 0)
			continue;
		for (i = 0; i < BURST_SIZE; i++) {
			rte_prefetch0(m[i + 1]);
			m[i]->tim = tim;
			m[i]->tim.ev.flow_id = flow_counter++ % nb_flows;
			m[i]->tim.ev.event_ptr = m[i];
			m[i]->timestamp = rte_get_timer_cycles();
			while (rte_event_timer_arm_burst(
			       adptr[flow_counter % nb_timer_adptrs],
			       (struct rte_event_timer **)&m[i], 1) != 1) {
				if (t->done)
					break;
				m[i]->timestamp = rte_get_timer_cycles();
			}
			arm_latency += rte_get_timer_cycles() - m[i]->timestamp;
		}
		count += BURST_SIZE;
	}
	fflush(stdout);
	rte_delay_ms(1000);
	printf("%s(): lcore %d Average event timer arm latency = %.3f us\n",
			__func__, rte_lcore_id(),
			count ? (float)(arm_latency / count) /
			(rte_get_timer_hz() / 1000000) : 0);
	return 0;
}

static inline int
perf_event_timer_producer_burst(void *arg)
{
	int i;
	struct prod_data *p  = arg;
	struct test_perf *t = p->t;
	struct evt_options *opt = t->opt;
	uint32_t flow_counter = 0;
	uint64_t count = 0;
	uint64_t arm_latency = 0;
	const uint8_t nb_timer_adptrs = opt->nb_timer_adptrs;
	const uint32_t nb_flows = t->nb_flows;
	const uint64_t nb_timers = opt->nb_timers;
	struct rte_mempool *pool = t->pool;
	struct perf_elt *m[BURST_SIZE + 1] = {NULL};
	struct rte_event_timer_adapter **adptr = t->timer_adptr;
	struct rte_event_timer tim;
	uint64_t timeout_ticks = opt->expiry_nsec / opt->timer_tick_nsec;

	memset(&tim, 0, sizeof(struct rte_event_timer));
	timeout_ticks =
		opt->optm_timer_tick_nsec
			? ceil((double)(timeout_ticks * opt->timer_tick_nsec) /
			       opt->optm_timer_tick_nsec)
			: timeout_ticks;
	timeout_ticks += timeout_ticks ? 0 : 1;
	tim.ev.event_type = RTE_EVENT_TYPE_TIMER;
	tim.ev.op = RTE_EVENT_OP_NEW;
	tim.ev.sched_type = t->opt->sched_type_list[0];
	tim.ev.queue_id = p->queue_id;
	tim.ev.priority = RTE_EVENT_DEV_PRIORITY_NORMAL;
	tim.state = RTE_EVENT_TIMER_NOT_ARMED;
	tim.timeout_ticks = timeout_ticks;

	if (opt->verbose_level > 1)
		printf("%s(): lcore %d\n", __func__, rte_lcore_id());

	while (count < nb_timers && t->done == false) {
		if (rte_mempool_get_bulk(pool, (void **)m, BURST_SIZE) < 0)
			continue;
		for (i = 0; i < BURST_SIZE; i++) {
			rte_prefetch0(m[i + 1]);
			m[i]->tim = tim;
			m[i]->tim.ev.flow_id = flow_counter++ % nb_flows;
			m[i]->tim.ev.event_ptr = m[i];
			m[i]->timestamp = rte_get_timer_cycles();
		}
		rte_event_timer_arm_tmo_tick_burst(
				adptr[flow_counter % nb_timer_adptrs],
				(struct rte_event_timer **)m,
				tim.timeout_ticks,
				BURST_SIZE);
		arm_latency += rte_get_timer_cycles() - m[i - 1]->timestamp;
		count += BURST_SIZE;
	}
	fflush(stdout);
	rte_delay_ms(1000);
	printf("%s(): lcore %d Average event timer arm latency = %.3f us\n",
			__func__, rte_lcore_id(),
			count ? (float)(arm_latency / count) /
			(rte_get_timer_hz() / 1000000) : 0);
	return 0;
}

static inline void
crypto_adapter_enq_op_new(struct prod_data *p)
{
	struct test_perf *t = p->t;
	const uint32_t nb_flows = t->nb_flows;
	const uint64_t nb_pkts = t->nb_pkts;
	struct rte_mempool *pool = t->pool;
	struct evt_options *opt = t->opt;
	uint16_t qp_id = p->ca.cdev_qp_id;
	uint8_t cdev_id = p->ca.cdev_id;
	uint64_t alloc_failures = 0;
	uint32_t flow_counter = 0;
	struct rte_crypto_op *op;
	uint16_t len, offset;
	struct rte_mbuf *m;
	uint64_t count = 0;

	if (opt->verbose_level > 1)
		printf("%s(): lcore %d queue %d cdev_id %u cdev_qp_id %u\n",
		       __func__, rte_lcore_id(), p->queue_id, p->ca.cdev_id,
		       p->ca.cdev_qp_id);

	offset = sizeof(struct perf_elt);
	len = RTE_MAX(RTE_ETHER_MIN_LEN + offset, opt->mbuf_sz);

	while (count < nb_pkts && t->done == false) {
		if (opt->crypto_op_type == RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
			struct rte_crypto_sym_op *sym_op;

			op = rte_crypto_op_alloc(t->ca_op_pool,
					 RTE_CRYPTO_OP_TYPE_SYMMETRIC);
			if (unlikely(op == NULL)) {
				alloc_failures++;
				continue;
			}

			m = rte_pktmbuf_alloc(pool);
			if (unlikely(m == NULL)) {
				alloc_failures++;
				rte_crypto_op_free(op);
				continue;
			}

			rte_pktmbuf_append(m, len);
			sym_op = op->sym;
			sym_op->m_src = m;
			sym_op->cipher.data.offset = offset;
			sym_op->cipher.data.length = len - offset;
			rte_crypto_op_attach_sym_session(
				op, p->ca.crypto_sess[flow_counter++ % nb_flows]);
		} else {
			struct rte_crypto_asym_op *asym_op;
			uint8_t *result;

			if (rte_mempool_get(pool, (void **)&result)) {
				alloc_failures++;
				continue;
			}

			op = rte_crypto_op_alloc(t->ca_op_pool,
					 RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
			if (unlikely(op == NULL)) {
				alloc_failures++;
				rte_mempool_put(pool, result);
				continue;
			}

			asym_op = op->asym;
			asym_op->modex.base.data = modex_test_case.base.data;
			asym_op->modex.base.length = modex_test_case.base.len;
			asym_op->modex.result.data = result;
			asym_op->modex.result.length = modex_test_case.result_len;
			rte_crypto_op_attach_asym_session(
				op, p->ca.crypto_sess[flow_counter++ % nb_flows]);
		}
		while (rte_cryptodev_enqueue_burst(cdev_id, qp_id, &op, 1) != 1 &&
				t->done == false)
			rte_pause();

		count++;
	}

	if (opt->verbose_level > 1 && alloc_failures)
		printf("%s(): lcore %d allocation failures: %"PRIu64"\n",
		       __func__, rte_lcore_id(), alloc_failures);
}

static inline void
crypto_adapter_enq_op_fwd(struct prod_data *p)
{
	const uint8_t dev_id = p->dev_id;
	const uint8_t port = p->port_id;
	struct test_perf *t = p->t;
	const uint32_t nb_flows = t->nb_flows;
	const uint64_t nb_pkts = t->nb_pkts;
	struct rte_mempool *pool = t->pool;
	struct evt_options *opt = t->opt;
	uint64_t alloc_failures = 0;
	uint32_t flow_counter = 0;
	struct rte_crypto_op *op;
	uint16_t len, offset;
	struct rte_event ev;
	struct rte_mbuf *m;
	uint64_t count = 0;

	if (opt->verbose_level > 1)
		printf("%s(): lcore %d port %d queue %d cdev_id %u cdev_qp_id %u\n",
		       __func__, rte_lcore_id(), port, p->queue_id,
		       p->ca.cdev_id, p->ca.cdev_qp_id);

	ev.event = 0;
	ev.op = RTE_EVENT_OP_NEW;
	ev.queue_id = p->queue_id;
	ev.sched_type = RTE_SCHED_TYPE_ATOMIC;
	ev.event_type = RTE_EVENT_TYPE_CPU;

	offset = sizeof(struct perf_elt);
	len = RTE_MAX(RTE_ETHER_MIN_LEN + offset, opt->mbuf_sz);

	while (count < nb_pkts && t->done == false) {
		if (opt->crypto_op_type == RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
			struct rte_crypto_sym_op *sym_op;

			op = rte_crypto_op_alloc(t->ca_op_pool,
					 RTE_CRYPTO_OP_TYPE_SYMMETRIC);
			if (unlikely(op == NULL)) {
				alloc_failures++;
				continue;
			}

			m = rte_pktmbuf_alloc(pool);
			if (unlikely(m == NULL)) {
				alloc_failures++;
				rte_crypto_op_free(op);
				continue;
			}

			rte_pktmbuf_append(m, len);
			sym_op = op->sym;
			sym_op->m_src = m;
			sym_op->cipher.data.offset = offset;
			sym_op->cipher.data.length = len - offset;
			rte_crypto_op_attach_sym_session(
				op, p->ca.crypto_sess[flow_counter++ % nb_flows]);
		} else {
			struct rte_crypto_asym_op *asym_op;
			uint8_t *result;

			if (rte_mempool_get(pool, (void **)&result)) {
				alloc_failures++;
				continue;
			}

			op = rte_crypto_op_alloc(t->ca_op_pool,
					 RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
			if (unlikely(op == NULL)) {
				alloc_failures++;
				rte_mempool_put(pool, result);
				continue;
			}

			asym_op = op->asym;
			asym_op->modex.base.data = modex_test_case.base.data;
			asym_op->modex.base.length = modex_test_case.base.len;
			asym_op->modex.result.data = result;
			asym_op->modex.result.length = modex_test_case.result_len;
			rte_crypto_op_attach_asym_session(
				op, p->ca.crypto_sess[flow_counter++ % nb_flows]);
		}
		ev.event_ptr = op;

		while (rte_event_crypto_adapter_enqueue(dev_id, port, &ev, 1) != 1 &&
		       t->done == false)
			rte_pause();

		count++;
	}

	if (opt->verbose_level > 1 && alloc_failures)
		printf("%s(): lcore %d allocation failures: %"PRIu64"\n",
		       __func__, rte_lcore_id(), alloc_failures);
}

static inline int
perf_event_crypto_producer(void *arg)
{
	struct prod_data *p = arg;
	struct evt_options *opt = p->t->opt;

	if (opt->crypto_adptr_mode == RTE_EVENT_CRYPTO_ADAPTER_OP_NEW)
		crypto_adapter_enq_op_new(p);
	else
		crypto_adapter_enq_op_fwd(p);

	return 0;
}

static int
perf_producer_wrapper(void *arg)
{
	struct prod_data *p  = arg;
	struct test_perf *t = p->t;
	bool burst = evt_has_burst_mode(p->dev_id);
	int ret = 0;

	/* In case of synthetic producer, launch perf_producer or
	 * perf_producer_burst depending on producer enqueue burst size
	 */
	if (t->opt->prod_type == EVT_PROD_TYPE_SYNT &&
			t->opt->prod_enq_burst_sz == 1)
		ret =  perf_producer(arg);
	else if (t->opt->prod_type == EVT_PROD_TYPE_SYNT &&
			t->opt->prod_enq_burst_sz > 1) {
		if (!burst)
			evt_err("This event device does not support burst mode");
		else
			ret = perf_producer_burst(arg);
	}
	else if (t->opt->prod_type == EVT_PROD_TYPE_EVENT_TIMER_ADPTR &&
			!t->opt->timdev_use_burst)
		ret =  perf_event_timer_producer(arg);
	else if (t->opt->prod_type == EVT_PROD_TYPE_EVENT_TIMER_ADPTR &&
			t->opt->timdev_use_burst)
		ret =  perf_event_timer_producer_burst(arg);
	else if (t->opt->prod_type == EVT_PROD_TYPE_EVENT_CRYPTO_ADPTR)
		ret =  perf_event_crypto_producer(arg);

	/* Unlink port to release any acquired HW resources*/
	rte_event_port_unlink(p->dev_id, p->port_id, &p->queue_id, 1);
	return ret;
}

static inline uint64_t
processed_pkts(struct test_perf *t)
{
	uint8_t i;
	uint64_t total = 0;

	for (i = 0; i < t->nb_workers; i++) {
		total += t->worker[i].processed_pkts;
        // printf("processed pkts at core %d is %lu\n", i, t->worker[i].processed_pkts);
    }

	return total;
}

static inline uint64_t
total_latency(struct test_perf *t)
{
	uint8_t i;
	uint64_t total = 0;

	for (i = 0; i < t->nb_workers; i++)
		total += t->worker[i].latency;

	return total;
}


int
perf_launch_lcores(struct evt_test *test, struct evt_options *opt,
		int (*worker)(void *))
{
	int ret, lcore_id;
	struct test_perf *t = evt_test_priv(test);

	int port_idx = 0;
	/* launch workers */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (!(opt->wlcores[lcore_id]))
			continue;

		ret = rte_eal_remote_launch(worker,
				 &t->worker[port_idx], lcore_id);
		if (ret) {
			evt_err("failed to launch worker %d", lcore_id);
			return ret;
		}
		port_idx++;
	}

    // port_idx++;
	/* launch producers */
	if (opt->call_main == 1) {
		rte_eal_mp_remote_launch(perf_producer_wrapper, &t->prod[port_idx], CALL_MAIN);
	}
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (!(opt->plcores[lcore_id]))
			continue;

        // struct MyParams lat_param = {
        //     .producer = &t->prod[port_idx],
        //     .worker = &t->worker[port_idx-1],
        // };

        // ret = rte_eal_remote_launch(perf_lat_producer_worker_burst,
		// 		&lat_param, lcore_id);
		ret = rte_eal_remote_launch(perf_producer_wrapper,
				&t->prod[port_idx], lcore_id);
		if (ret) {
			evt_err("failed to launch perf_producer %d", lcore_id);
			return ret;
		}
        printf("producer core %d with port id %d.\n", lcore_id, port_idx);
		port_idx++;
	}

	const uint64_t total_pkts = t->outstand_pkts;

	uint64_t dead_lock_cycles = rte_get_timer_cycles();
	int64_t dead_lock_remaining  =  total_pkts;
	const uint64_t dead_lock_sample = rte_get_timer_hz() * 5;

	uint64_t perf_cycles = rte_get_timer_cycles();
	int64_t perf_remaining  = total_pkts;
	const uint64_t perf_sample = rte_get_timer_hz();

	static float total_mpps;
	static uint64_t samples;

	const uint64_t freq_mhz = rte_get_timer_hz() / 1000000;
	int64_t remaining = t->outstand_pkts - processed_pkts(t);
    
	uint64_t test_perf_cycles = rte_get_timer_cycles();


    int i, j;
    uint64_t port_xstat_ids[MAX_PORTS_QUEUES][RTE_DIM(port_xstat_strs)];
    uint64_t port_xstat_vals[MAX_PORTS_QUEUES][RTE_DIM(port_xstat_strs)];
    uint64_t prev_port_xstat_vals[MAX_PORTS_QUEUES][RTE_DIM(port_xstat_strs)] = {0};

    uint64_t queue_xstat_ids[MAX_PORTS_QUEUES][RTE_DIM(queue_xstat_strs)];
    uint64_t queue_xstat_vals[MAX_PORTS_QUEUES][RTE_DIM(queue_xstat_strs)] = {0};
    uint64_t prev_queue_xstat_vals[MAX_PORTS_QUEUES][RTE_DIM(queue_xstat_strs)] = {0};

    uint64_t dev_xstat_ids[RTE_DIM(dev_xstat_strs)];
    uint64_t dev_xstat_vals[RTE_DIM(dev_xstat_strs)];

    if (opt->use_dlb) {
        ret = rte_event_dev_xstats_get(opt->dev_id,
                        RTE_EVENT_DEV_XSTATS_DEVICE,
                        0,
                        &dev_xstat_ids[DEV_LDB_POOL_SIZE],
                        &dev_xstat_vals[DEV_LDB_POOL_SIZE],
                        1);
        if (ret != 1)
            rte_panic("Failed to get ldb pool size\n");

        ret = rte_event_dev_xstats_get(opt->dev_id,
                        RTE_EVENT_DEV_XSTATS_DEVICE,
                        0,
                        &dev_xstat_ids[DEV_DIR_POOL_SIZE],
                        &dev_xstat_vals[DEV_DIR_POOL_SIZE],
                        1);

        if (ret != 1)
            rte_panic("Failed to get dir pool size\n");

        ret = rte_event_dev_xstats_get(opt->dev_id,
                        RTE_EVENT_DEV_XSTATS_DEVICE,
                        0,
                        &dev_xstat_ids[DEV_POOL_SIZE],
                        &dev_xstat_vals[DEV_POOL_SIZE],
                        1);
        if (ret != 1)
            rte_panic("Failed to get pool size\n");
    }


    uint64_t total_polls, zero_polls;
    float zero_poll_pct;
	float zero_poll_pct_prev = 100.0;
    int num_ports = perf_nb_event_ports(opt);

    struct rte_event_dev_info dev_info;
	ret = rte_event_dev_info_get(opt->dev_id, &dev_info);
	if (ret) {
		evt_err("failed to get eventdev info %d", opt->dev_id);
		return ret;
	}

    if (opt->use_dlb) {
        for (i = 0; i < num_ports; i++) {
            get_xstats_ids(opt->dev_id,
                    RTE_EVENT_DEV_XSTATS_PORT,
                    port_xstat_strs,
                    port_xstat_ids[i],
                    RTE_DIM(port_xstat_strs),
                    i);
        }

        for (i = 0; i < 1; i++) {
            get_xstats_ids(opt->dev_id,
                    RTE_EVENT_DEV_XSTATS_QUEUE,
                    queue_xstat_strs,
                    queue_xstat_ids[i],
                    RTE_DIM(queue_xstat_strs),
                    i);
        }
    }

    int max_wlcores = evt_nr_active_lcores(opt->wlcores);
    int nb_wlcores = evt_nr_active_lcores(opt->wlcores);
    int flag = 0;
    int is_ldb;
	uint64_t depth, max_depth;
    int dynamic_allocation = 0;

	while (t->done == false) {
		const uint64_t new_cycles = rte_get_timer_cycles();

		if ((new_cycles - perf_cycles) > perf_sample) {
            printf("\n");
			const uint64_t latency = total_latency(t);
			const uint64_t pkts = processed_pkts(t);

            if (dynamic_allocation == 1 && opt->use_dlb) {
                // ==============================
                /* Initialize prev_sched_throughput[i] */
                ret = rte_event_dev_xstats_get(opt->dev_id,
                        RTE_EVENT_DEV_XSTATS_DEVICE,
                        0,
                        dev_xstat_ids,
                        dev_xstat_vals,
                        RTE_DIM(dev_xstat_strs));
                if (ret != RTE_DIM(dev_xstat_strs))
                    rte_panic("Failed to get device xstats\n");
                max_depth = dev_xstat_vals[DEV_LDB_POOL_SIZE];

                total_polls = 0;
                zero_polls = 0;
                nb_wlcores = evt_nr_active_lcores(opt->wlcores);
                for (i = 0; i < nb_wlcores; i++) {
                    ret = rte_event_dev_xstats_get(opt->dev_id,
                                    RTE_EVENT_DEV_XSTATS_PORT,
                                    i,
                                    port_xstat_ids[i],
                                    port_xstat_vals[i],
                                    RTE_DIM(port_xstat_strs));
                    if (ret != RTE_DIM(port_xstat_strs))
                        rte_panic("Failed to get port %u's xstats (ret: %d)\n", i, ret);
                    total_polls += port_xstat_vals[i][TOTAL_POLLS] - prev_port_xstat_vals[i][TOTAL_POLLS];
                    zero_polls += port_xstat_vals[i][ZERO_POLLS] - prev_port_xstat_vals[i][ZERO_POLLS];
                    zero_poll_pct = ((port_xstat_vals[i][ZERO_POLLS] - prev_port_xstat_vals[i][ZERO_POLLS]) * 100.0f) / (port_xstat_vals[i][TOTAL_POLLS] - prev_port_xstat_vals[i][TOTAL_POLLS]);
                    evt_log("port [%u] zero poll percent %f.", i, zero_poll_pct);
                    evt_log("rx ok is: %lu", port_xstat_vals[i][RX_OK]-prev_port_xstat_vals[i][RX_OK]);
                    prev_port_xstat_vals[i][TOTAL_POLLS] = port_xstat_vals[i][TOTAL_POLLS];
                    prev_port_xstat_vals[i][ZERO_POLLS] = port_xstat_vals[i][ZERO_POLLS];
                    prev_port_xstat_vals[i][RX_OK] = port_xstat_vals[i][RX_OK];
                }
                zero_poll_pct = (zero_polls * 100.0f) / total_polls;
                evt_log("%d workers' overall zero poll percent %f.", nb_wlcores, zero_poll_pct);

                // for (i = 0; i < 1; i++) {
                //     ret = rte_event_dev_xstats_get(opt->dev_id,
                //                     RTE_EVENT_DEV_XSTATS_QUEUE,
                //                     i,
                //                     queue_xstat_ids[i],
                //                     queue_xstat_vals[i],
                //                     RTE_DIM(queue_xstat_strs));
                //     if (ret != RTE_DIM(queue_xstat_strs))
                //         rte_panic("Failed to get queue %u's xstats\n", i);
                // }
                // is_ldb = queue_xstat_vals[0][QUEUE_IS_LOAD_BALANCED];
                // depth = queue_xstat_vals[0][CURRENT_DEPTH];
                // evt_log("Queue 0's max depth is %" PRIu64 ", current depth is %" PRIu64 ", in flight is %" PRIu64 ".", max_depth, depth, dev_xstat_vals[DEV_INFL_EVENTS]);
                // if (max_depth == 0) {  /* DLB 2.5 uses combined credit pool */
                //     max_depth = dev_xstat_vals[DEV_POOL_SIZE];
                //     depth = queue_xstat_vals[0][CURRENT_DEPTH];
                // } 
                // if (max_depth != 0) {
                //     evt_log("Queue 0's max depth is %lu, current depth is %lu.", max_depth, depth);
                // }

                if (zero_poll_pct > 90) {
                    if (nb_wlcores > 1) {
                        // close one worker core with largest port number
                        ret = rte_event_port_unlink(opt->dev_id, nb_wlcores-1, NULL, 0);
                        opt->wlcores[opt->wlcore_idx[nb_wlcores-1]] = 0;
                        if (ret == 0) evt_err("failed to unlink port");
                        evt_log("worker core %d with port %d is unlinked.", opt->wlcore_idx[nb_wlcores-1], nb_wlcores-1);
                        for (j = 0; j < RTE_DIM(port_xstat_strs); j++) {
                            port_xstat_ids[nb_wlcores-1][j] = 0;
                        }
                    }
                } 
                else if (30 < zero_poll_pct && zero_poll_pct < 60) {
                    if (nb_wlcores < max_wlcores) {
                        // increase worker core count
                        opt->wlcores[opt->wlcore_idx[nb_wlcores]] = 1;
                        ret = rte_event_port_link(opt->dev_id, nb_wlcores, NULL, NULL, 0);
                        if (ret == 0) evt_err("failed to link port");
                        evt_log("worker core %d with port %d is linked with %d queues.", opt->wlcore_idx[nb_wlcores], nb_wlcores, ret);
                        ret = rte_eal_remote_launch(worker, &t->worker[nb_wlcores], opt->wlcore_idx[nb_wlcores]);
                        if (ret) {
                            evt_err("failed to launch worker %d", opt->wlcore_idx[nb_wlcores]);
                            return ret;
                        }
                        get_xstats_ids(opt->dev_id,
                            RTE_EVENT_DEV_XSTATS_PORT,
                            port_xstat_strs,
                            port_xstat_ids[nb_wlcores],
                            RTE_DIM(port_xstat_strs),
                            nb_wlcores);
                        nb_wlcores = evt_nr_active_lcores(opt->wlcores);
                    }
                } 
                else if (zero_poll_pct <= 30) {
                    while (nb_wlcores < max_wlcores) {
                        // increase worker core count
                        opt->wlcores[opt->wlcore_idx[nb_wlcores]] = 1;
                        ret = rte_event_port_link(opt->dev_id, nb_wlcores, NULL, NULL, 0);
                        if (ret == 0) evt_err("failed to link port");
                        evt_log("worker core %d with port %d is linked with %d queues.", opt->wlcore_idx[nb_wlcores], nb_wlcores, ret);
                        ret = rte_eal_remote_launch(worker, &t->worker[nb_wlcores], opt->wlcore_idx[nb_wlcores]);
                        if (ret) {
                            evt_err("failed to launch worker %d", opt->wlcore_idx[nb_wlcores]);
                            return ret;
                        }
                        get_xstats_ids(opt->dev_id,
                            RTE_EVENT_DEV_XSTATS_PORT,
                            port_xstat_strs,
                            port_xstat_ids[nb_wlcores],
                            RTE_DIM(port_xstat_strs),
                            nb_wlcores);
                        nb_wlcores = evt_nr_active_lcores(opt->wlcores);
                    }
                }

                
                // if ((new_cycles - test_perf_cycles) > 2*perf_sample) {
                //     if (flag == 0) {
                //         // close one worker core with largest port number
                //         ret = rte_event_port_unlink(opt->dev_id, 1, NULL, 0);
                //         opt->wlcores[opt->wlcore_idx[1]] = 0;
                //         if (ret <= 0) evt_err("failed to unlink port");
                //         evt_log("worker core %d with port %d is unlinked with %d queues.", opt->wlcore_idx[1], 0, ret);
                //         flag = 1;
                //         rte_mb();
                //     }
                //     else {
                //         // increase worker core count
                //         opt->wlcores[opt->wlcore_idx[1]] = 1;
                //         ret = rte_event_port_link(opt->dev_id, 1, NULL, NULL, 0);
                //         if (ret <= 0) evt_err("failed to link port");
                //         evt_log("worker core %d with port %d is linked with %d queues.", opt->wlcore_idx[1], 0, ret);
                //         // uint8_t queues_list[RTE_EVENT_MAX_QUEUES_PER_DEV];
                //         // uint8_t priorities_list[RTE_EVENT_MAX_QUEUES_PER_DEV];
                //         // ret = rte_event_port_links_get(opt->dev_id, 0, queues_list, priorities_list);
                //         // evt_log("worker core %d with port %d is linked with %d queues %d %d %d %d.", opt->wlcore_idx[0], 0, ret, queues_list[0], queues_list[1], queues_list[2], queues_list[3]);
                //         ret = rte_eal_remote_launch(worker, &t->worker[1], opt->wlcore_idx[1]);
                //         if (ret) {
                //             evt_err("failed to launch worker %d", opt->wlcore_idx[1]);
                //             return ret;
                //         }
                //         flag = 0;
                //         rte_mb();
                //     }
                //     // t->nb_workers = evt_nr_active_lcores(opt->wlcores);
                //     // evt_log("t->nb_workers is %d", t->nb_workers);
                //     test_perf_cycles = new_cycles;

                //     // uint8_t queues[RTE_EVENT_MAX_QUEUES_PER_DEV];
                //     // uint8_t priorities[RTE_EVENT_MAX_QUEUES_PER_DEV];
                //     // evt_log("port 0 has %d links", rte_event_port_links_get(opt->dev_id, 0, queues, priorities));
                //     // evt_log("port 1 has %d links", rte_event_port_links_get(opt->dev_id, 1, queues, priorities));
                //     // evt_log("port 2 has %d links", rte_event_port_links_get(opt->dev_id, 2, queues, priorities));
                // }

                // ==============================
            }

			remaining = t->outstand_pkts - pkts;
			float mpps = (float)(perf_remaining-remaining)/1000000;

			perf_remaining = remaining;
			perf_cycles = new_cycles;
			total_mpps += mpps;
			++samples;
			if (opt->fwd_latency && pkts > 0) {
				printf(CLGRN"\r%.3f mpps avg %.3f mpps [avg fwd latency %.3f us] \n"CLNRM,
					mpps, total_mpps/samples,
					(float)(latency/pkts)/freq_mhz);
			} else {
				printf(CLGRN"\rsample %ld: %.3f mpps avg %.3f mpps \n"CLNRM,
					samples, mpps, total_mpps/samples);
			}
			fflush(stdout);

			if (remaining <= 0) {
				t->result = EVT_TEST_SUCCESS;
				if (opt->prod_type == EVT_PROD_TYPE_SYNT ||
				    opt->prod_type ==
					    EVT_PROD_TYPE_EVENT_TIMER_ADPTR ||
				    opt->prod_type ==
					    EVT_PROD_TYPE_EVENT_CRYPTO_ADPTR) {
					t->done = true;
					break;
				}
			}
		}

		if (new_cycles - dead_lock_cycles > dead_lock_sample &&
		    (opt->prod_type == EVT_PROD_TYPE_SYNT ||
		     opt->prod_type == EVT_PROD_TYPE_EVENT_TIMER_ADPTR ||
		     opt->prod_type == EVT_PROD_TYPE_EVENT_CRYPTO_ADPTR)) {
			remaining = t->outstand_pkts - processed_pkts(t);
			if (dead_lock_remaining == remaining) {
				rte_event_dev_dump(opt->dev_id, stdout);
				evt_err("No schedules for seconds, deadlock");
				t->done = true;
				break;
			}
			dead_lock_remaining = remaining;
			dead_lock_cycles = new_cycles;
		}
	}
	printf("\n");


	return 0;
}


// setup rx adapter
static int
perf_event_rx_adapter_setup(struct evt_options *opt, uint8_t stride,
		struct rte_event_port_conf prod_conf)
{
	int ret = 0;
	uint16_t prod;
	struct rte_event_eth_rx_adapter_queue_conf queue_conf;

    // uint16_t eth_prod = 0;

	memset(&queue_conf, 0,
			sizeof(struct rte_event_eth_rx_adapter_queue_conf));
	queue_conf.ev.sched_type = opt->sched_type_list[0];
	RTE_ETH_FOREACH_DEV(prod) {
		uint32_t cap;

		ret = rte_event_eth_rx_adapter_caps_get(opt->dev_id,
				prod, &cap);
		if (ret) {
			evt_err("failed to get event rx adapter[%d]"
					" capabilities",
					opt->dev_id);
			return ret;
		}
		queue_conf.ev.queue_id = prod * stride;

        /* TODO: Add more RX queues to adapter */
        for (uint16_t q = 0; q < opt->nb_rx_adapters; q++) {
            ret = rte_event_eth_rx_adapter_create(q, opt->dev_id,
                    &prod_conf);
            if (ret) {
                evt_err("failed to create rx adapter[%d]", prod);
                return ret;
            }

            queue_conf.ev.queue_id = q;
            ret = rte_event_eth_rx_adapter_queue_add(q, prod, q,
                    &queue_conf);
            if (ret) {
                evt_err("failed to add rx queues to adapter[%d]", prod);
                return ret;
            }

            if (!(cap & RTE_EVENT_ETH_RX_ADAPTER_CAP_INTERNAL_PORT)) {
                uint32_t service_id;

                rte_event_eth_rx_adapter_service_id_get(q,
                        &service_id);

                printf("cap is %x, constant is %x.\n", cap, RTE_EVENT_ETH_RX_ADAPTER_CAP_INTERNAL_PORT);
                evt_log("%s(): Setup service core... Service id is %d.", __func__, service_id);

                ret = evt_service_setup(service_id);
                if (ret) {
                    evt_err("Failed to setup service core"
                            " for Rx adapter\n");
                    return ret;
                }
            }
        }
	}

	return ret;
}

static int
perf_event_timer_adapter_setup(struct test_perf *t)
{
	int i;
	int ret;
	struct rte_event_timer_adapter_info adapter_info;
	struct rte_event_timer_adapter *wl;
	uint8_t nb_producers = evt_nr_active_lcores(t->opt->plcores);
	uint8_t flags = RTE_EVENT_TIMER_ADAPTER_F_ADJUST_RES;

	if (nb_producers == 1)
		flags |= RTE_EVENT_TIMER_ADAPTER_F_SP_PUT;

	for (i = 0; i < t->opt->nb_timer_adptrs; i++) {
		struct rte_event_timer_adapter_conf config = {
			.event_dev_id = t->opt->dev_id,
			.timer_adapter_id = i,
			.timer_tick_ns = t->opt->timer_tick_nsec,
			.max_tmo_ns = t->opt->max_tmo_nsec,
			.nb_timers = t->opt->pool_sz,
			.flags = flags,
		};

		wl = rte_event_timer_adapter_create(&config);
		if (wl == NULL) {
			evt_err("failed to create event timer ring %d", i);
			return rte_errno;
		}

		memset(&adapter_info, 0,
				sizeof(struct rte_event_timer_adapter_info));
		rte_event_timer_adapter_get_info(wl, &adapter_info);
		t->opt->optm_timer_tick_nsec = adapter_info.min_resolution_ns;

		if (!(adapter_info.caps &
				RTE_EVENT_TIMER_ADAPTER_CAP_INTERNAL_PORT)) {
			uint32_t service_id = -1U;

			rte_event_timer_adapter_service_id_get(wl,
					&service_id);
			ret = evt_service_setup(service_id);
			if (ret) {
				evt_err("Failed to setup service core"
						" for timer adapter\n");
				return ret;
			}
			rte_service_runstate_set(service_id, 1);
		}
		t->timer_adptr[i] = wl;
	}
	return 0;
}

static int
perf_event_crypto_adapter_setup(struct test_perf *t, struct prod_data *p)
{
	struct evt_options *opt = t->opt;
	uint32_t cap;
	int ret;

	ret = rte_event_crypto_adapter_caps_get(p->dev_id, p->ca.cdev_id, &cap);
	if (ret) {
		evt_err("Failed to get crypto adapter capabilities");
		return ret;
	}

	if (((opt->crypto_adptr_mode == RTE_EVENT_CRYPTO_ADAPTER_OP_NEW) &&
	     !(cap & RTE_EVENT_CRYPTO_ADAPTER_CAP_INTERNAL_PORT_OP_NEW)) ||
	    ((opt->crypto_adptr_mode == RTE_EVENT_CRYPTO_ADAPTER_OP_FORWARD) &&
	     !(cap & RTE_EVENT_CRYPTO_ADAPTER_CAP_INTERNAL_PORT_OP_FWD))) {
		evt_err("crypto adapter %s mode unsupported\n",
			opt->crypto_adptr_mode ? "OP_FORWARD" : "OP_NEW");
		return -ENOTSUP;
	} else if (!(cap & RTE_EVENT_CRYPTO_ADAPTER_CAP_SESSION_PRIVATE_DATA)) {
		evt_err("Storing crypto session not supported");
		return -ENOTSUP;
	}

	if (cap & RTE_EVENT_CRYPTO_ADAPTER_CAP_INTERNAL_PORT_QP_EV_BIND) {
		struct rte_event_crypto_adapter_queue_conf conf;

		memset(&conf, 0, sizeof(conf));
		conf.ev.sched_type = RTE_SCHED_TYPE_ATOMIC;
		conf.ev.queue_id = p->queue_id;
		ret = rte_event_crypto_adapter_queue_pair_add(
			TEST_PERF_CA_ID, p->ca.cdev_id, p->ca.cdev_qp_id, &conf);
	} else {
		ret = rte_event_crypto_adapter_queue_pair_add(
			TEST_PERF_CA_ID, p->ca.cdev_id, p->ca.cdev_qp_id, NULL);
	}

	return ret;
}

static void *
cryptodev_sym_sess_create(struct prod_data *p, struct test_perf *t)
{
	struct rte_crypto_sym_xform cipher_xform;
	void *sess;

	cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_NULL;
	cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
	cipher_xform.next = NULL;

	sess = rte_cryptodev_sym_session_create(p->ca.cdev_id, &cipher_xform,
			t->ca_sess_pool);
	if (sess == NULL) {
		evt_err("Failed to create sym session");
		return NULL;
	}

	return sess;
}

static void *
cryptodev_asym_sess_create(struct prod_data *p, struct test_perf *t)
{
	const struct rte_cryptodev_asymmetric_xform_capability *capability;
	struct rte_cryptodev_asym_capability_idx cap_idx;
	struct rte_crypto_asym_xform xform;
	void *sess;

	xform.next = NULL;
	xform.xform_type = RTE_CRYPTO_ASYM_XFORM_MODEX;
	cap_idx.type = xform.xform_type;
	capability = rte_cryptodev_asym_capability_get(p->ca.cdev_id, &cap_idx);
	if (capability == NULL) {
		evt_err("Device doesn't support MODEX. Test Skipped\n");
		return NULL;
	}

	xform.modex.modulus.data = modex_test_case.modulus.data;
	xform.modex.modulus.length = modex_test_case.modulus.len;
	xform.modex.exponent.data = modex_test_case.exponent.data;
	xform.modex.exponent.length = modex_test_case.exponent.len;

	if (rte_cryptodev_asym_session_create(p->ca.cdev_id, &xform,
			t->ca_asym_sess_pool, &sess)) {
		evt_err("Failed to create asym session");
		return NULL;
	}

	return sess;
}

int
perf_event_dev_port_setup(struct evt_test *test, struct evt_options *opt,
				uint8_t stride, uint8_t nb_queues,
				const struct rte_event_port_conf *port_conf)
{
	struct test_perf *t = evt_test_priv(test);
	uint16_t port, prod;
	int ret = -1;

	/* setup one port per worker, linking to all queues */
	for (port = 0; port < evt_nr_active_lcores(opt->wlcores);
				port++) {
		struct worker_data *w = &t->worker[port];

		w->dev_id = opt->dev_id;
		w->port_id = port;
		w->t = t;
		w->processed_pkts = 0;
		w->latency = 0;

		struct rte_event_port_conf conf = *port_conf;
		// conf.event_port_cfg |= RTE_EVENT_PORT_CFG_HINT_WORKER;
		conf.event_port_cfg |= RTE_EVENT_PORT_CFG_HINT_CONSUMER;

		ret = rte_event_port_setup(opt->dev_id, port, &conf);
		if (ret) {
			evt_err("failed to setup port %d", port);
			return ret;
		}

		if (opt->nb_dir_queues) {
			uint8_t queues[EVT_MAX_PRODUCERS] = {0};
			uint8_t prio[EVT_MAX_PRODUCERS] = {0};
			uint8_t i;

			for (i = 0; i < nb_queues - opt->nb_dir_queues; ++i)
				queues[i] = opt->lb_queue_ids[i];
			ret = rte_event_port_link(opt->dev_id, port, queues, prio, i);
		} else {
			ret = rte_event_port_link(opt->dev_id, port, NULL, NULL, 0);
		}
		if (ret != nb_queues - opt->nb_dir_queues) {
			evt_err("linked %d queues, failed to link all queues to port %d", ret, port);
			return -EINVAL;
		}
	}

	/* port for producers, no links */
    // ====== Use ethernet device as producer!!!!!
	if (opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR) {
		for ( ; port < perf_nb_event_ports(opt); port++) {
			struct prod_data *p = &t->prod[port];
			p->t = t;
		}

		struct rte_event_port_conf conf = *port_conf;
		conf.event_port_cfg |= RTE_EVENT_PORT_CFG_HINT_PRODUCER;

        /* TODO: Add more RX queues to adapter */
        ret = perf_event_rx_adapter_setup(opt, stride, conf);
        if (ret)
            return ret;
	} else if (opt->prod_type == EVT_PROD_TYPE_EVENT_TIMER_ADPTR) {
		prod = 0;
		for ( ; port < perf_nb_event_ports(opt); port++) {
			struct prod_data *p = &t->prod[port];
			p->queue_id = prod * stride;
			p->t = t;
			prod++;
		}

		ret = perf_event_timer_adapter_setup(t);
		if (ret)
			return ret;
	} else if (opt->prod_type == EVT_PROD_TYPE_EVENT_CRYPTO_ADPTR) {
		struct rte_event_port_conf conf = *port_conf;
		uint8_t cdev_id = 0;
		uint16_t qp_id = 0;

		ret = rte_event_crypto_adapter_create(TEST_PERF_CA_ID,
						      opt->dev_id, &conf, 0);
		if (ret) {
			evt_err("Failed to create crypto adapter");
			return ret;
		}

		prod = 0;
		for (; port < perf_nb_event_ports(opt); port++) {
			union rte_event_crypto_metadata m_data;
			struct prod_data *p = &t->prod[port];
			uint32_t flow_id;

			if (qp_id == rte_cryptodev_queue_pair_count(cdev_id)) {
				cdev_id++;
				qp_id = 0;
			}

			p->dev_id = opt->dev_id;
			p->port_id = port;
			p->queue_id = prod * stride;
			p->ca.cdev_id = cdev_id;
			p->ca.cdev_qp_id = qp_id;
			p->ca.crypto_sess = rte_zmalloc_socket(
				NULL, sizeof(void *) * t->nb_flows,
				RTE_CACHE_LINE_SIZE, opt->socket_id);
			p->t = t;

			ret = perf_event_crypto_adapter_setup(t, p);
			if (ret)
				return ret;

			m_data.request_info.cdev_id = p->ca.cdev_id;
			m_data.request_info.queue_pair_id = p->ca.cdev_qp_id;
			m_data.response_info.sched_type = RTE_SCHED_TYPE_ATOMIC;
			m_data.response_info.queue_id = p->queue_id;

			for (flow_id = 0; flow_id < t->nb_flows; flow_id++) {
				m_data.response_info.flow_id = flow_id;
				if (opt->crypto_op_type ==
						RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
					void *sess;

					sess = cryptodev_sym_sess_create(p, t);
					if (sess == NULL)
						return -ENOMEM;

					ret = rte_cryptodev_session_event_mdata_set(
						cdev_id,
						sess,
						RTE_CRYPTO_OP_TYPE_SYMMETRIC,
						RTE_CRYPTO_OP_WITH_SESSION,
						&m_data, sizeof(m_data));
					if (ret)
						return ret;
					p->ca.crypto_sess[flow_id] = sess;
				} else {
					void *sess;

					sess = cryptodev_asym_sess_create(p, t);
					if (sess == NULL)
						return -ENOMEM;
					ret = rte_cryptodev_session_event_mdata_set(
						cdev_id,
						sess,
						RTE_CRYPTO_OP_TYPE_ASYMMETRIC,
						RTE_CRYPTO_OP_WITH_SESSION,
						&m_data, sizeof(m_data));
					if (ret)
						return ret;
					p->ca.crypto_sess[flow_id] = sess;
				}
			}

			conf.event_port_cfg |=
				RTE_EVENT_PORT_CFG_HINT_PRODUCER |
				RTE_EVENT_PORT_CFG_HINT_CONSUMER;

			ret = rte_event_port_setup(opt->dev_id, port, &conf);
			if (ret) {
				evt_err("failed to setup port %d", port);
				return ret;
			}

			qp_id++;
			prod++;
		}
	} else {
		prod = 0;
		for ( ; port < perf_nb_event_ports(opt); port++) {
			struct prod_data *p = &t->prod[port];

			p->dev_id = opt->dev_id;
			p->port_id = port;
			p->queue_id = prod * stride;
			p->t = t;

			struct rte_event_port_conf conf = *port_conf;
			conf.event_port_cfg |=
				RTE_EVENT_PORT_CFG_HINT_PRODUCER |
				RTE_EVENT_PORT_CFG_HINT_CONSUMER;
			if (opt->nb_dir_queues)
				conf.event_port_cfg |= RTE_EVENT_PORT_CFG_SINGLE_LINK;

			ret = rte_event_port_setup(opt->dev_id, port, &conf);
			if (ret) {
				evt_err("failed to setup port %d", port);
				return ret;
			}
			if (opt->nb_dir_queues) {
				uint8_t prio = 0;
				
				/*
				 * For KW errors
				 */
				port = port % RTE_EVENT_MAX_PORTS_PER_DEV;
				prod = prod % RTE_EVENT_MAX_PORTS_PER_DEV;

				if (rte_event_port_link(opt->dev_id, port,
							&opt->dir_queue_ids[prod],
							&prio, 1) != 1) {
					evt_err("failed to link dir queue %d "
						"to port %d",
						opt->dir_queue_ids[prod], port);
					return -EINVAL;
				}
			}
            // rte_event_port_link(opt->dev_id, port,
			// 				NULL,
			// 				NULL, 0);
			prod++;
		}
	}

	return ret;
}

int
perf_opt_check(struct evt_options *opt, uint64_t nb_queues)
{
	unsigned int lcores;

	/* N producer + N worker + main when producer cores are used
	 * Else N worker + main when Rx adapter is used
	 */
	lcores = opt->prod_type == EVT_PROD_TYPE_SYNT ? 3 : 2;

	if (rte_lcore_count() < lcores) {
		evt_err("test need minimum %d lcores", lcores);
		return -1;
	}

	/* Validate worker lcores */
	if (evt_lcores_has_overlap(opt->wlcores, rte_get_main_lcore())) {
		evt_err("worker lcores overlaps with main lcore");
		return -1;
	}
	if (evt_lcores_has_overlap_multi(opt->wlcores, opt->plcores)) {
		evt_err("worker lcores overlaps producer lcores");
		return -1;
	}
	if (evt_has_disabled_lcore(opt->wlcores)) {
		evt_err("one or more workers lcores are not enabled");
		return -1;
	}
	if (!evt_has_active_lcore(opt->wlcores)) {
		evt_err("minimum one worker is required");
		return -1;
	}

	if (opt->prod_type == EVT_PROD_TYPE_SYNT ||
	    opt->prod_type == EVT_PROD_TYPE_EVENT_TIMER_ADPTR ||
	    opt->prod_type == EVT_PROD_TYPE_EVENT_CRYPTO_ADPTR) {
		/* Validate producer lcores */
		if (evt_lcores_has_overlap(opt->plcores,
					rte_get_main_lcore())) {
			evt_err("producer lcores overlaps with main lcore");
			return -1;
		}
		if (evt_has_disabled_lcore(opt->plcores)) {
			evt_err("one or more producer lcores are not enabled");
			return -1;
		}
		if (!evt_has_active_lcore(opt->plcores)) {
			evt_err("minimum one producer is required");
			return -1;
		}
	}

	if (evt_has_invalid_stage(opt))
		return -1;

	if (evt_has_invalid_sched_type(opt))
		return -1;

	if (nb_queues > EVT_MAX_QUEUES) {
		evt_err("number of queues exceeds %d", EVT_MAX_QUEUES);
		return -1;
	}
	if (perf_nb_event_ports(opt) > EVT_MAX_PORTS) {
		evt_err("number of ports exceeds %d", EVT_MAX_PORTS);
		return -1;
	}

	/* Fixups */
	if ((opt->nb_stages == 1 &&
			opt->prod_type != EVT_PROD_TYPE_EVENT_TIMER_ADPTR) &&
			opt->fwd_latency) {
		evt_info("fwd_latency is valid when nb_stages > 1, disabling");
		opt->fwd_latency = 0;
	}

	if (opt->fwd_latency && !opt->q_priority) {
		evt_info("enabled queue priority for latency measurement");
		opt->q_priority = 1;
	}
	if (opt->nb_pkts == 0)
		opt->nb_pkts = INT64_MAX/evt_nr_active_lcores(opt->plcores);

	return 0;
}

void
perf_opt_dump(struct evt_options *opt, uint8_t nb_queues)
{
	evt_dump("nb_prod_lcores", "%d", evt_nr_active_lcores(opt->plcores));
	evt_dump_producer_lcores(opt);
	evt_dump("nb_worker_lcores", "%d", evt_nr_active_lcores(opt->wlcores));
	evt_dump_worker_lcores(opt);
	evt_dump_nb_stages(opt);
	evt_dump("nb_evdev_ports", "%d", perf_nb_event_ports(opt));
	evt_dump("nb_evdev_queues", "%d", nb_queues);
	evt_dump_queue_priority(opt);
	evt_dump_sched_type_list(opt);
	evt_dump_producer_type(opt);
	evt_dump("prod_enq_burst_sz", "%d", opt->prod_enq_burst_sz);
}

static void
perf_event_port_flush(uint8_t dev_id __rte_unused, struct rte_event ev,
		      void *args)
{
	rte_mempool_put(args, ev.event_ptr);
}

void
perf_worker_cleanup(struct rte_mempool *const pool, uint8_t dev_id,
		    uint8_t port_id, struct rte_event events[], uint16_t nb_enq,
		    uint16_t nb_deq)
{
	int i;

	if (nb_deq) {
		for (i = nb_enq; i < nb_deq; i++)
			rte_mempool_put(pool, events[i].event_ptr);

		for (i = 0; i < nb_deq; i++)
			events[i].op = RTE_EVENT_OP_RELEASE;
		rte_event_enqueue_burst(dev_id, port_id, events, nb_deq);
	}
	rte_event_port_quiesce(dev_id, port_id, perf_event_port_flush, pool);
}

void
perf_eventdev_destroy(struct evt_test *test, struct evt_options *opt)
{
	int i;
	struct test_perf *t = evt_test_priv(test);

	if (opt->prod_type == EVT_PROD_TYPE_EVENT_TIMER_ADPTR) {
		for (i = 0; i < opt->nb_timer_adptrs; i++)
			rte_event_timer_adapter_stop(t->timer_adptr[i]);
	}
	rte_event_dev_stop(opt->dev_id);
	rte_event_dev_close(opt->dev_id);
}

static inline void
perf_elt_init(struct rte_mempool *mp, void *arg __rte_unused,
	    void *obj, unsigned i __rte_unused)
{
	memset(obj, 0, mp->elt_size);
}

#define NB_RX_DESC			1024
#define NB_TX_DESC			1024
int
perf_ethdev_setup(struct evt_test *test, struct evt_options *opt)
{
	uint16_t i;
	int ret;
	struct test_perf *t = evt_test_priv(test);
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.mq_mode = RTE_ETH_MQ_RX_RSS,
		},
		.rx_adv_conf = {
			.rss_conf = {
				.rss_key = NULL,
				.rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP,
			},
		},
	};

	if (opt->prod_type != EVT_PROD_TYPE_ETH_RX_ADPTR)
		return 0;

	if (!rte_eth_dev_count_avail()) {
		evt_err("No ethernet ports found.");
		return -ENODEV;
	}

	RTE_ETH_FOREACH_DEV(i) {
		struct rte_eth_dev_info dev_info;
		struct rte_eth_conf local_port_conf = port_conf;

		ret = rte_eth_dev_info_get(i, &dev_info);
		if (ret != 0) {
			evt_err("Error during getting device (port %u) info: %s\n",
					i, strerror(-ret));
			return ret;
		}

		local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
			dev_info.flow_type_rss_offloads;
		if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
				port_conf.rx_adv_conf.rss_conf.rss_hf) {
			evt_info("Port %u modified RSS hash function based on hardware support,"
				"requested:%#"PRIx64" configured:%#"PRIx64"\n",
				i,
				port_conf.rx_adv_conf.rss_conf.rss_hf,
				local_port_conf.rx_adv_conf.rss_conf.rss_hf);
		}

        /* Modified nb_rx_queue based on number of Rx adapters, nb_tx_queues based on number of # wlcores */
		if (rte_eth_dev_configure(i, opt->nb_rx_adapters, evt_nr_active_lcores(opt->wlcores), &local_port_conf) < 0) {
			evt_err("Failed to configure eth port [%d]", i);
			return -EINVAL;
		}

        /* TODO: MODIFY TO ADD MULTIPLE QUEUES */
        for (int32_t q = 0; q < opt->nb_rx_adapters; q++) {
            if (rte_eth_rx_queue_setup(i, q, NB_RX_DESC,
                    rte_socket_id(), NULL, t->pool) < 0) {
                evt_err("Failed to setup eth port [%d] rx_queue: %d.",
                        i, q);
                return -EINVAL;
            }
        }

        for (int32_t q = 0; q < evt_nr_active_lcores(opt->wlcores); q++) {
            if (rte_eth_tx_queue_setup(i, q, NB_TX_DESC,
                        rte_socket_id(), NULL) < 0) {
                evt_err("Failed to setup eth port [%d] tx_queue: %d.",
                        i, q);
                return -EINVAL;
            }
        }

		ret = rte_eth_promiscuous_enable(i);
		if (ret != 0) {
			evt_err("Failed to enable promiscuous mode for eth port [%d]: %s",
				i, rte_strerror(-ret));
			return ret;
		}
	}

	return 0;
}

void
perf_ethdev_rx_stop(struct evt_test *test, struct evt_options *opt)
{
	uint16_t i;
	RTE_SET_USED(test);
	printf("Stopping RX adapter\n");

	if (opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR) {
		RTE_ETH_FOREACH_DEV(i) {
            /* TODO */
            for (uint16_t q = 0; q < opt->nb_rx_adapters; q++) {
                rte_event_eth_rx_adapter_stop(q);
                rte_event_eth_rx_adapter_queue_del(q, i, -1);
			    rte_eth_dev_rx_queue_stop(i, q);
            }
            // rte_event_eth_rx_adapter_stop(i);
            // rte_event_eth_rx_adapter_queue_del(i, i, -1);
			// rte_eth_dev_rx_queue_stop(i, 0);
		}
	}
}

void
perf_ethdev_destroy(struct evt_test *test, struct evt_options *opt)
{
	uint16_t i;
	RTE_SET_USED(test);
	printf("Destroying ethdev\n");

	if (opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR) {
		RTE_ETH_FOREACH_DEV(i) {
            rte_event_eth_tx_adapter_stop(i);
            rte_event_eth_tx_adapter_queue_del(i, i, -1);
            /* TODO */
            for (uint16_t q = 0; q < evt_nr_active_lcores(opt->wlcores); q++) {
                rte_eth_dev_tx_queue_stop(i, q);
            }
            // rte_event_eth_tx_adapter_stop(i);
            // rte_event_eth_tx_adapter_queue_del(i, i, -1);
			// rte_eth_dev_tx_queue_stop(i, 0);
			rte_eth_dev_stop(i);
		}
	}
}

int
perf_cryptodev_setup(struct evt_test *test, struct evt_options *opt)
{
	uint8_t cdev_count, cdev_id, nb_plcores, nb_qps;
	struct test_perf *t = evt_test_priv(test);
	unsigned int max_session_size;
	uint32_t nb_sessions;
	int ret;

	if (opt->prod_type != EVT_PROD_TYPE_EVENT_CRYPTO_ADPTR)
		return 0;

	cdev_count = rte_cryptodev_count();
	if (cdev_count == 0) {
		evt_err("No crypto devices available\n");
		return -ENODEV;
	}

	t->ca_op_pool = rte_crypto_op_pool_create(
		"crypto_op_pool", opt->crypto_op_type, opt->pool_sz,
		128, sizeof(union rte_event_crypto_metadata),
		rte_socket_id());
	if (t->ca_op_pool == NULL) {
		evt_err("Failed to create crypto op pool");
		return -ENOMEM;
	}

	nb_sessions = evt_nr_active_lcores(opt->plcores) * t->nb_flows;
	t->ca_asym_sess_pool = rte_cryptodev_asym_session_pool_create(
		"ca_asym_sess_pool", nb_sessions, 0,
		sizeof(union rte_event_crypto_metadata), SOCKET_ID_ANY);
	if (t->ca_asym_sess_pool == NULL) {
		evt_err("Failed to create sym session pool");
		ret = -ENOMEM;
		goto err;
	}

	max_session_size = 0;
	for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
		unsigned int session_size;

		session_size =
			rte_cryptodev_sym_get_private_session_size(cdev_id);
		if (session_size > max_session_size)
			max_session_size = session_size;
	}

	t->ca_sess_pool = rte_cryptodev_sym_session_pool_create(
		"ca_sess_pool", nb_sessions, max_session_size, 0,
		sizeof(union rte_event_crypto_metadata), SOCKET_ID_ANY);
	if (t->ca_sess_pool == NULL) {
		evt_err("Failed to create sym session pool");
		ret = -ENOMEM;
		goto err;
	}

	/*
	 * Calculate number of needed queue pairs, based on the amount of
	 * available number of logical cores and crypto devices. For instance,
	 * if there are 4 cores and 2 crypto devices, 2 queue pairs will be set
	 * up per device.
	 */
	nb_plcores = evt_nr_active_lcores(opt->plcores);
	nb_qps = (nb_plcores % cdev_count) ? (nb_plcores / cdev_count) + 1 :
					     nb_plcores / cdev_count;
	for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
		struct rte_cryptodev_qp_conf qp_conf;
		struct rte_cryptodev_config conf;
		struct rte_cryptodev_info info;
		int qp_id;

		rte_cryptodev_info_get(cdev_id, &info);
		if (nb_qps > info.max_nb_queue_pairs) {
			evt_err("Not enough queue pairs per cryptodev (%u)",
				nb_qps);
			ret = -EINVAL;
			goto err;
		}

		conf.nb_queue_pairs = nb_qps;
		conf.socket_id = SOCKET_ID_ANY;
		conf.ff_disable = RTE_CRYPTODEV_FF_SECURITY;

		ret = rte_cryptodev_configure(cdev_id, &conf);
		if (ret) {
			evt_err("Failed to configure cryptodev (%u)", cdev_id);
			goto err;
		}

		qp_conf.nb_descriptors = NB_CRYPTODEV_DESCRIPTORS;
		qp_conf.mp_session = t->ca_sess_pool;

		for (qp_id = 0; qp_id < conf.nb_queue_pairs; qp_id++) {
			ret = rte_cryptodev_queue_pair_setup(
				cdev_id, qp_id, &qp_conf,
				rte_cryptodev_socket_id(cdev_id));
			if (ret) {
				evt_err("Failed to setup queue pairs on cryptodev %u\n",
					cdev_id);
				goto err;
			}
		}
	}

	return 0;
err:
	for (cdev_id = 0; cdev_id < cdev_count; cdev_id++)
		rte_cryptodev_close(cdev_id);

	rte_mempool_free(t->ca_op_pool);
	rte_mempool_free(t->ca_sess_pool);
	rte_mempool_free(t->ca_asym_sess_pool);

	return ret;
}

void
perf_cryptodev_destroy(struct evt_test *test, struct evt_options *opt)
{
	uint8_t cdev_id, cdev_count = rte_cryptodev_count();
	struct test_perf *t = evt_test_priv(test);
	uint16_t port;

	if (opt->prod_type != EVT_PROD_TYPE_EVENT_CRYPTO_ADPTR)
		return;

	for (port = t->nb_workers; port < perf_nb_event_ports(opt); port++) {
		void *sess;
		struct prod_data *p = &t->prod[port];
		uint32_t flow_id;
		uint8_t cdev_id;

		for (flow_id = 0; flow_id < t->nb_flows; flow_id++) {
			sess = p->ca.crypto_sess[flow_id];
			cdev_id = p->ca.cdev_id;
			rte_cryptodev_sym_session_free(cdev_id, sess);
		}

		rte_event_crypto_adapter_queue_pair_del(
			TEST_PERF_CA_ID, p->ca.cdev_id, p->ca.cdev_qp_id);
	}

	rte_event_crypto_adapter_free(TEST_PERF_CA_ID);

	for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
		rte_cryptodev_stop(cdev_id);
		rte_cryptodev_close(cdev_id);
	}

	rte_mempool_free(t->ca_op_pool);
	rte_mempool_free(t->ca_sess_pool);
	rte_mempool_free(t->ca_asym_sess_pool);
}

int
perf_mempool_setup(struct evt_test *test, struct evt_options *opt)
{
	struct test_perf *t = evt_test_priv(test);

	if (opt->prod_type == EVT_PROD_TYPE_SYNT ||
			opt->prod_type == EVT_PROD_TYPE_EVENT_TIMER_ADPTR) {
		printf("Element size of mempool is %ld\n", sizeof(struct perf_elt));
		t->pool = rte_mempool_create(test->name, /* mempool name */
				opt->pool_sz, /* number of elements*/
				sizeof(struct perf_elt), /* element size*/
				512, /* cache size*/
				0, NULL, NULL,
				perf_elt_init, /* obj constructor */
				NULL, opt->socket_id, 0); /* flags */
	} else if (opt->prod_type == EVT_PROD_TYPE_EVENT_CRYPTO_ADPTR &&
			opt->crypto_op_type == RTE_CRYPTO_OP_TYPE_ASYMMETRIC)  {
		t->pool = rte_mempool_create(test->name, /* mempool name */
				opt->pool_sz, /* number of elements*/
				sizeof(struct perf_elt) + modex_test_case.result_len,
				/* element size*/
				512, /* cache size*/
				0, NULL, NULL,
				NULL, /* obj constructor */
				NULL, opt->socket_id, 0); /* flags */
	} else {
		t->pool = rte_pktmbuf_pool_create(test->name, /* mempool name */
				opt->pool_sz, /* number of elements*/
				512, /* cache size*/
				0,
				RTE_MBUF_DEFAULT_BUF_SIZE,
				opt->socket_id); /* flags */

		// debug:
		// printf("[perf_mempool_setup]: the mempool start address is %p", t->pool->pool_data);

	}

	if (t->pool == NULL) {
		evt_err("failed to create mempool");
		return -ENOMEM;
	}

	return 0;
}

void
perf_mempool_destroy(struct evt_test *test, struct evt_options *opt)
{
	RTE_SET_USED(opt);
	struct test_perf *t = evt_test_priv(test);

	rte_mempool_free(t->pool);
}

int
perf_test_setup(struct evt_test *test, struct evt_options *opt)
{
	void *test_perf;

	test_perf = rte_zmalloc_socket(test->name, sizeof(struct test_perf),
				RTE_CACHE_LINE_SIZE, opt->socket_id);
	if (test_perf  == NULL) {
		evt_err("failed to allocate test_perf memory");
		goto nomem;
	}
	test->test_priv = test_perf;

	struct test_perf *t = evt_test_priv(test);

	if (opt->prod_type == EVT_PROD_TYPE_EVENT_TIMER_ADPTR) {
		t->outstand_pkts = opt->nb_timers *
			evt_nr_active_lcores(opt->plcores);
		t->nb_pkts = opt->nb_timers;
	} else {
		t->outstand_pkts = opt->nb_pkts *
			evt_nr_active_lcores(opt->plcores);
		t->nb_pkts = opt->nb_pkts;
	}

	t->nb_workers = evt_nr_active_lcores(opt->wlcores);
	t->done = false;
	t->nb_flows = opt->nb_flows;
	t->result = EVT_TEST_FAILED;
	t->opt = opt;
	memcpy(t->sched_type_list, opt->sched_type_list,
			sizeof(opt->sched_type_list));
	return 0;
nomem:
	return -ENOMEM;
}

void
perf_test_destroy(struct evt_test *test, struct evt_options *opt)
{
	RTE_SET_USED(opt);

	rte_free(test->test_priv);
}
