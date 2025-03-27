/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 */

#include "test_perf_common.h"

/* See http://doc.dpdk.org/guides/tools/testeventdev.html for test details */

// Calculate number of queues to be established
int
perf_queue_nb_event_queues(struct evt_options *opt)
{
	/* nb_queues = number of producers * number of stages */
    uint8_t nb_prod = opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR ?
		opt->nb_rx_adapters : evt_nr_active_lcores(opt->plcores);
	// uint8_t nb_prod = opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR ?
	// 	rte_eth_dev_count_avail() : evt_nr_active_lcores(opt->plcores);
	/* Directed ports need to be linked to directed queues. So increase the
	 * number of queues by number of producers.
	 */
	if (opt->nb_dir_queues)
		return nb_prod * (opt->nb_stages + 1);
	else
		return nb_prod * opt->nb_stages;
}

static __rte_always_inline void
fwd_event(struct rte_event *const ev, uint8_t *const sched_type_list,
		const uint8_t nb_stages)
{
	ev->queue_id++;
	ev->sched_type = sched_type_list[ev->queue_id % nb_stages];
	ev->op = RTE_EVENT_OP_FORWARD;
	ev->event_type = RTE_EVENT_TYPE_CPU;
}

static int
perf_queue_worker(void *arg, const int enable_fwd_latency)
{
	struct perf_elt *pe = NULL;
	uint16_t enq = 0, deq = 0;
	struct rte_event ev;
	PERF_WORKER_INIT;
	uint8_t stage;


	while (t->done == false) {
		deq = rte_event_dequeue_burst(dev, port, &ev, 1, 0);

		if (!deq) {
			rte_pause();
			continue;
		}

		if (prod_crypto_type && (ev.event_type == RTE_EVENT_TYPE_CRYPTODEV)) {
			if (perf_handle_crypto_ev(&ev, &pe, enable_fwd_latency))
				continue;
		} else {
			pe = ev.event_ptr;
		}

		stage = ev.queue_id % nb_stages;
		if (enable_fwd_latency && !prod_timer_type && stage == 0)
		/* first q in pipeline, mark timestamp to compute fwd latency */
			perf_mark_fwd_latency(pe);

		/* last stage in pipeline */
		if (unlikely(stage == laststage)) {
			if (enable_fwd_latency)
				cnt = perf_process_last_stage_latency(pool, prod_crypto_type,
					&ev, w, bufs, sz, cnt);
			else
				cnt = perf_process_last_stage(pool, prod_crypto_type,
					&ev, w, bufs, sz, cnt);
		} else {
			fwd_event(&ev, sched_type_list, nb_stages);
			do {
				enq = rte_event_enqueue_burst(dev, port, &ev, 1);
			} while (!enq && !t->done);
		}
	}

	perf_worker_cleanup(pool, dev, port, &ev, enq, deq);

	return 0;
}

// Compute latency stats
static int cmpfunc (const void * a, const void * b)
{
    if (*(double*)a > *(double*)b) return 1;
    else if (*(double*)a < *(double*)b) return -1;
    else return 0;
}

static int
perf_queue_worker_burst(void *arg, const int enable_fwd_latency)
{
	/* +1 to avoid prefetch out of array check */
	struct rte_event ev[BURST_SIZE + 1];
	uint16_t enq = 0, nb_rx = 0;
	struct perf_elt *pe = NULL;
	PERF_WORKER_INIT;
	uint8_t stage;
	uint16_t i;

    // ==== calculate dequeue rate
	uint64_t hz = rte_get_timer_hz();
    uint64_t prev_tsc, cur_tsc, diff_tsc;
    prev_tsc = rte_get_timer_cycles();
	// ==== calculate dequeue rate


    /* Get ethernet port 0 MAC addr */
    struct rte_ether_addr my_ether_addr;
    if (opt->e2e_latency == 1 && opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR) {
        int retval = rte_eth_macaddr_get(0, &my_ether_addr);
        if (retval != 0) {
            fprintf(stderr, "Error during rte_eth_macaddr_get\n");
            return retval;
        }
        printf("lcore %d Port %hu MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
            " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            rte_lcore_id(), 0, my_ether_addr.addr_bytes[0], my_ether_addr.addr_bytes[1], my_ether_addr.addr_bytes[2],
            my_ether_addr.addr_bytes[3], my_ether_addr.addr_bytes[4], my_ether_addr.addr_bytes[5]);
    }

    size_t offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);  // pointer to the dummy process delay
    uint64_t dummy_process_delay = 0;  // unit of nanoseconds

    uint64_t lat_arr[10000];
    int latency_idx = 0;

    /* Time */
    // MODIFY HERE: TEST LATENCY PERIOD
    uint16_t interval = 1;  // unit of s
    uint64_t interval_cycles = (uint64_t) (interval * hz / 1000.0);
    uint64_t tx_prev_tsc, tx_cur_tsc, tx_diff_tsc;
    tx_prev_tsc = rte_get_timer_cycles();
    uint16_t nb_tx = 0;
    uint64_t c2c_lat;
    struct perf_elt * ev_ptr_temp;
    evt_log("Tx queue is %d. nb_stages is %d, last stage is %d.", rte_lcore_id()%evt_nr_active_lcores(opt->wlcores), nb_stages, laststage);

    uint8_t queues[RTE_EVENT_MAX_QUEUES_PER_DEV];
	uint8_t priorities[RTE_EVENT_MAX_QUEUES_PER_DEV];

    tsc_hz = rte_get_timer_hz();
    // printf("tsc_hz: %lu\n", tsc_hz);
	while (t->done == false) {
        if (rte_event_port_links_get(dev, port, queues, priorities) == 0) {
            break;
        }

		nb_rx = rte_event_dequeue_burst(dev, port, ev, BURST_SIZE, 0);

		if (!nb_rx) {
			rte_pause();
			continue;
		}

		for (i = 0; i < nb_rx; i++) {
        	tx_cur_tsc = rte_get_timer_cycles();

			if (prod_crypto_type && (ev[i].event_type == RTE_EVENT_TYPE_CRYPTODEV)) {
				if (perf_handle_crypto_ev(&ev[i], &pe, enable_fwd_latency))
					continue;
			}

			// Test the event contents
			// printf("use perf_queue_worker_burst to get packet in %lu, %p, %lu, %p\n", &ev[i], &ev[i], ev[i].mbuf, ev[i].mbuf->buf_addr);

			stage = ev[i].queue_id % nb_stages;
			if (enable_fwd_latency && !prod_timer_type && stage == 0) {
				rte_prefetch0(ev[i+1].event_ptr);
				/* first queue in pipeline.
				 * mark time stamp to compute fwd latency
				 */
				perf_mark_fwd_latency(ev[i].event_ptr);
			}

            // =========== Perform dummy process
            if (opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR) {
                dummy_process_delay = *(uint64_t *)(rte_pktmbuf_mtod_offset(ev[i].mbuf, char *, offset));
                // rte_delay_us_sleep(1);
                // printf("dummy process delay is %lu\n", dummy_process_delay);
                if (dummy_process_delay > 0) {
                    delay_cycles(dummy_process_delay);
				}
            } else {
                dummy_process_delay = opt->dummy_delay;
                if (dummy_process_delay > 0) {
                    delay_cycles(dummy_process_delay);
				}
            }
            // ===========

            // =========== Send back packets
            tx_diff_tsc = tx_cur_tsc - tx_prev_tsc;

            if (opt->e2e_latency == 1 && opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR && tx_diff_tsc > interval_cycles) {
            // if (opt->e2e_latency == 1 && opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR) {
                struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(ev[i].mbuf, struct rte_ether_hdr *);
                rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
                rte_ether_addr_copy(&my_ether_addr, &eth_hdr->src_addr);
                nb_tx = rte_eth_tx_burst(0, rte_lcore_id()%evt_nr_active_lcores(opt->wlcores), &ev[i].mbuf, 1);
                tx_prev_tsc = tx_cur_tsc;
                wlcore_queue_pkts[(int)rte_lcore_id()][(int)ev[i].queue_id] += nb_tx;
                continue;
            }


			// ========= Measure core to core latency
			if (opt->prod_type != EVT_PROD_TYPE_ETH_RX_ADPTR) {
				((uint64_t *)ev[i].mbuf)[0] += 1;
				ev_ptr_temp = ev[i].event_ptr;
				if (wlcore_queue_pkts[(int)rte_lcore_id()][(int)ev[i].queue_id] % 10000 == 0) {
					c2c_lat = rte_get_timer_cycles() - ev_ptr_temp->timestamp;

					c2c_latency_array[(int)rte_lcore_id()][(int)ev[i].queue_id] += c2c_lat;

					lat_arr[latency_idx] = c2c_lat;
					latency_idx = (latency_idx+1)%10000;
				}
			}

            // ==========================


			/* last stage in pipeline */
			if (unlikely(stage == laststage)) {
				if (enable_fwd_latency)
					cnt = perf_process_last_stage_latency(pool,
						prod_crypto_type, &ev[i], w, bufs, sz, cnt);
				else
					cnt = perf_process_last_stage(pool, prod_crypto_type,
						&ev[i], w, bufs, sz, cnt);

				ev[i].op = RTE_EVENT_OP_RELEASE;
			} else {
				// fwd_event(&ev[i], sched_type_list, nb_stages);
			}

			// STATS TRACKING
			wlcore_queue_pkts[(int)rte_lcore_id()][(int)ev[i].queue_id] += 1;
			// printf("%ld, wlcore %d processed packets from queue %d\n", wlcore_queue_pkts[dev][ev[i].queue_id], dev, ev[i].queue_id);
		}

        rte_mb();

		// enq = rte_event_enqueue_burst(dev, port, ev, nb_rx);
		// while (enq < nb_rx && !t->done) {
		// 	enq += rte_event_enqueue_burst(dev, port,
		// 					ev + enq, nb_rx - enq);
		// }
	}

    // // =========== PRINT WORKER STATS
	int stats_nb_queues = 0;
	uint8_t nb_prod = opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR ?
		opt->nb_rx_adapters : evt_nr_active_lcores(opt->plcores);
	if (opt->nb_dir_queues)
		stats_nb_queues = nb_prod * (opt->nb_stages + 1);
	else
		stats_nb_queues = nb_prod * opt->nb_stages;

    // ==== calculate dequeue rate
	cur_tsc = rte_get_timer_cycles();
	diff_tsc = cur_tsc - prev_tsc;
    uint64_t count = 0;
    uint64_t total_lat = 0;
    for (uint8_t i = 0; i < stats_nb_queues; i++) {
        count += wlcore_queue_pkts[rte_lcore_id()][i];
        total_lat += c2c_latency_array[rte_lcore_id()][i];
	}
    double pkt_rate  = (double) count / diff_tsc * hz / 1000000.0;
	printf("\033[1;36mwlcore %d dequeue pkt_rate is %lf\033[0m\n", rte_lcore_id(), pkt_rate);
	
    // ==== calculate core to core latency
    double avg_lat = (double) total_lat / hz * 1000000.0 / count;
	printf("\033[1;36mwlcore %d average core to core latency is %lf\033[0m\n", rte_lcore_id(), avg_lat);
    

	if (opt->prod_type != EVT_PROD_TYPE_ETH_RX_ADPTR) {
		double c2c_latency[10000];
		int valid_size = 0;
		double total_latency = 0;
		for (int i = 0; i < 10000; i++) {
			c2c_latency[i] = (double) lat_arr[i] / hz * 1000000.0;
			total_latency += c2c_latency[i];
			if (c2c_latency[i] > 0) valid_size++;
		}

		qsort(c2c_latency, valid_size, sizeof(double), cmpfunc);
		printf("==== E2E Latency ====\n");
		printf("Valid latency size: %u\n", valid_size);
		printf("Average latency: %.3f us\n", total_latency/valid_size);
		printf("min%% tail latency: %.3f us\n", c2c_latency[(int) 0]);
		printf("25%% tail latency: %.3f us\n", c2c_latency[(int) (0.25 * valid_size)]);
		printf("50%% tail latency: %.3f us\n", c2c_latency[(int) (0.50 * valid_size)]);
		printf("75%% tail latency: %.3f us\n", c2c_latency[(int) (0.75 * valid_size)]);
		printf("90%% tail latency: %.3f us\n", c2c_latency[(int) (0.9 * valid_size)]);
		printf("95%% tail latency: %.3f us\n", c2c_latency[(int) (0.95 * valid_size)]);
		printf("99%% tail latency: %.3f us\n", c2c_latency[(int) (0.99 * valid_size)]);
		printf("max%% tail latency: %.3f us\n", c2c_latency[(int) (valid_size - 1)]);
	}

	// printf("====== Worker %d ======\n", rte_lcore_id());
	// for (uint8_t i = 0; i < stats_nb_queues; i++) {
	// 	printf("\033[1;36mwlcore %d processed %ld packets (%lf %%) from queue %d\033[0m\n", rte_lcore_id(), wlcore_queue_pkts[rte_lcore_id()][i], wlcore_queue_pkts[rte_lcore_id()][i]*1.0/count*100.0, i);
	// }
	// =========== PRINT WORKER STATS

	perf_worker_cleanup(pool, dev, port, ev, enq, nb_rx);

	return 0;
}

static int
worker_wrapper(void *arg)
{
	struct worker_data *w  = arg;
	struct evt_options *opt = w->t->opt;

	const bool burst = evt_has_burst_mode(w->dev_id);
	const int fwd_latency = opt->fwd_latency;

	// ==== whether the device has burst mode
	// if (burst) printf("Device has burst mode\n");
	// else printf("Device does not have burst mode\n");

	/* allow compiler to optimize */
	if (!burst && !fwd_latency)
		return perf_queue_worker(arg, 0);
	else if (!burst && fwd_latency)
		return perf_queue_worker(arg, 1);
	else if (burst && !fwd_latency)
		return perf_queue_worker_burst(arg, 0);
	else if (burst && fwd_latency)
		return perf_queue_worker_burst(arg, 1);

	rte_panic("invalid worker\n");
}

static int
perf_queue_launch_lcores(struct evt_test *test, struct evt_options *opt)
{
	return perf_launch_lcores(test, opt, worker_wrapper);
}

static int
perf_queue_eventdev_setup(struct evt_test *test, struct evt_options *opt)
{
	uint8_t queue;
	int nb_stages = opt->nb_stages;
	int ret;
	int nb_ports;
	int nb_queues;
	uint16_t prod;
	struct rte_event_dev_info dev_info;
	struct test_perf *t = evt_test_priv(test);

	nb_ports = evt_nr_active_lcores(opt->wlcores);
	if (opt->prod_type != EVT_PROD_TYPE_ETH_RX_ADPTR &&
	    opt->prod_type != EVT_PROD_TYPE_EVENT_TIMER_ADPTR) {
		nb_ports += evt_nr_active_lcores(opt->plcores);
		// WHY WE NEED TO SETUP DIR QUEUES HERE???
		// opt->nb_dir_queues = evt_nr_active_lcores(opt->plcores);
		opt->nb_dir_queues = 0;
	}

    /* TODO: whether we need to setup more event queues here in order to setup multiple Rx queues? */
	nb_queues = perf_queue_nb_event_queues(opt);
    printf("number of queues: %d.\n", nb_queues);

	ret = rte_event_dev_info_get(opt->dev_id, &dev_info);
	if (ret) {
		evt_err("failed to get eventdev info %d", opt->dev_id);
		return ret;
	}
    // struct rte_device * dev_info_details;
    // dev_info_details = dev_info.dev;
    printf("==== Device Info ====\n");
    printf("Device driver name: %s\n", dev_info.driver_name);
    // printf("Device name: %s\n", dev_info_details->name);
    printf("Max number of flows is %ld\n", dev_info.max_event_queue_flows);
	// configure eventd devices
    printf("number of ports is %d.\n", nb_ports);
	ret = evt_configure_eventdev(opt, nb_queues, nb_ports);
	if (ret) {
		evt_err("failed to configure eventdev %d", opt->dev_id);
		return ret;
	}

	struct rte_event_queue_conf q_conf = {
			.priority = RTE_EVENT_DEV_PRIORITY_NORMAL,
			.nb_atomic_flows = opt->nb_flows,
			.nb_atomic_order_sequences = opt->nb_flows,
	};
	uint8_t num_lb_q = 0, num_dir_q = 0;
	/* queue configurations */
	for (queue = 0; queue < nb_queues; queue++) {
		if (queue >= (nb_queues - opt->nb_dir_queues)) {
			q_conf.event_queue_cfg = RTE_EVENT_QUEUE_CFG_SINGLE_LINK;
			opt->dir_queue_ids[num_dir_q++] = queue;
		} else {
            q_conf.schedule_type =
				(opt->sched_type_list[0]);
			// q_conf.schedule_type =
			// 	(opt->sched_type_list[queue % nb_stages]);
			if (opt->q_priority) {
				// uint8_t stage_pos = queue % nb_stages;
				uint8_t stage_pos = queue % nb_queues;
				/* Configure event queues(stage 0 to stage n) with
				 * RTE_EVENT_DEV_PRIORITY_LOWEST to
				 * RTE_EVENT_DEV_PRIORITY_HIGHEST.
				 */
				// uint8_t step = RTE_EVENT_DEV_PRIORITY_LOWEST /
				// 			   (nb_stages - 1);
                uint8_t step = RTE_EVENT_DEV_PRIORITY_LOWEST /
							   (nb_queues - 1);
				/* Higher prio for the queues closer to last stage */
				// q_conf.priority = RTE_EVENT_DEV_PRIORITY_LOWEST -
				// 				  (step * stage_pos);
			}
			opt->lb_queue_ids[num_lb_q++] = queue;
		}
		ret = rte_event_queue_setup(opt->dev_id, queue, &q_conf);
		if (ret) {
			evt_err("failed to setup queue=%d", queue);
			return ret;
		}
	}

	if (opt->wkr_deq_dep > dev_info.max_event_port_dequeue_depth)
		opt->wkr_deq_dep = dev_info.max_event_port_dequeue_depth;

	/* port configuration */
	const struct rte_event_port_conf p_conf = {
			.dequeue_depth = opt->wkr_deq_dep,
			.enqueue_depth = dev_info.max_event_port_dequeue_depth,
			.new_event_threshold = dev_info.max_num_events,
			.event_port_cfg = 0,
	};

	ret = perf_event_dev_port_setup(test, opt, nb_stages /* stride */,
					nb_queues, &p_conf);
	if (ret)
		return ret;

	if (!evt_has_distributed_sched(opt->dev_id)) {
		uint32_t service_id;
		rte_event_dev_service_id_get(opt->dev_id, &service_id);
		ret = evt_service_setup(service_id);
		if (ret) {
			evt_err("No service lcore found to run event dev.");
			return ret;
		}
	}

	ret = rte_event_dev_start(opt->dev_id);
	if (ret) {
		evt_err("failed to start eventdev %d", opt->dev_id);
		return ret;
	}

	if (opt->prod_type == EVT_PROD_TYPE_ETH_RX_ADPTR) {
        /* TODO: add multiple ethdev instances */
		RTE_ETH_FOREACH_DEV(prod) {
			ret = rte_eth_dev_start(prod);
			if (ret) {
				evt_err("Ethernet dev [%d] failed to start. Using synthetic producer",
						prod);
				return ret;
			}

            for (uint16_t q = 0; q < opt->nb_rx_adapters; q++) {
                ret = rte_event_eth_rx_adapter_start(q);
                if (ret) {
                    evt_err("Rx adapter[%d] start failed", q);
                    return ret;
                }
                printf("%s: Port[%d] using Rx adapter[%d] started\n",
                        __func__, prod, q);
            }
		}
	} else if (opt->prod_type == EVT_PROD_TYPE_EVENT_TIMER_ADPTR) {
		for (prod = 0; prod < opt->nb_timer_adptrs; prod++) {
			ret = rte_event_timer_adapter_start(
					t->timer_adptr[prod]);
			if (ret) {
				evt_err("failed to Start event timer adapter %d"
						, prod);
				return ret;
			}
		}
	} else if (opt->prod_type == EVT_PROD_TYPE_EVENT_CRYPTO_ADPTR) {
		uint8_t cdev_id, cdev_count;

		cdev_count = rte_cryptodev_count();
		for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
			ret = rte_cryptodev_start(cdev_id);
			if (ret) {
				evt_err("Failed to start cryptodev %u",
					cdev_id);
				return ret;
			}
		}
	}

	return 0;
}

static void
perf_queue_opt_dump(struct evt_options *opt)
{
	evt_dump_fwd_latency(opt);
	perf_opt_dump(opt, perf_queue_nb_event_queues(opt));
}

static int
perf_queue_opt_check(struct evt_options *opt)
{
	return perf_opt_check(opt, perf_queue_nb_event_queues(opt));
}

static bool
perf_queue_capability_check(struct evt_options *opt)
{
	struct rte_event_dev_info dev_info;

	rte_event_dev_info_get(opt->dev_id, &dev_info);
	if (dev_info.max_event_queues < perf_queue_nb_event_queues(opt) ||
			dev_info.max_event_ports < perf_nb_event_ports(opt)) {
		evt_err("not enough eventdev queues=%d/%d or ports=%d/%d",
			perf_queue_nb_event_queues(opt),
			dev_info.max_event_queues,
			perf_nb_event_ports(opt), dev_info.max_event_ports);
	}

	return true;
}

static const struct evt_test_ops perf_queue =  {
	.cap_check          = perf_queue_capability_check,
	.opt_check          = perf_queue_opt_check,
	.opt_dump           = perf_queue_opt_dump,
	.test_setup         = perf_test_setup,
	.mempool_setup      = perf_mempool_setup,
	.ethdev_setup	    = perf_ethdev_setup,
	.cryptodev_setup    = perf_cryptodev_setup,
	.ethdev_rx_stop     = perf_ethdev_rx_stop,
	.eventdev_setup     = perf_queue_eventdev_setup,
	.launch_lcores      = perf_queue_launch_lcores,
	.eventdev_destroy   = perf_eventdev_destroy,
	.mempool_destroy    = perf_mempool_destroy,
	.ethdev_destroy	    = perf_ethdev_destroy,
	.cryptodev_destroy  = perf_cryptodev_destroy,
	.test_result        = perf_test_result,
	.test_destroy       = perf_test_destroy,
};

EVT_TEST_REGISTER(perf_queue);
