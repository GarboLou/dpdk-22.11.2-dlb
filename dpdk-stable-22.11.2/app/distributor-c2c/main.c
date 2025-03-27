/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2017 Intel Corporation
 */

#include <getopt.h>
#include <inttypes.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_distributor.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_pause.h>
#include <rte_power.h>
#include <rte_prefetch.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS ((64 * 1024) - 1)
#define MBUF_CACHE_SIZE 128
#define BURST_SIZE 64
#define SCHED_RX_RING_SZ 8192
#define SCHED_TX_RING_SZ 65536
#define BURST_SIZE_TX 32
#define NUM_PRODUCER_CORES 8

#define RTE_LOGTYPE_DISTRAPP RTE_LOGTYPE_USER1

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_RESET "\x1b[0m"

/* mask of enabled ports */
static uint32_t enabled_port_mask;
volatile uint8_t quit_signal;
volatile uint8_t quit_signal_rx;
volatile uint8_t quit_signal_dist;
volatile uint8_t quit_signal_work;
unsigned int num_workers;
static int iters = 10000;

static volatile struct app_stats {
  struct {
    uint64_t rx_pkts;
    uint64_t returned_pkts;
    uint64_t enqueued_pkts;
    uint64_t enqdrop_pkts;
  } rx __rte_cache_aligned;
  int pad1 __rte_cache_aligned;

  struct {
    uint64_t in_pkts;
    uint64_t ret_pkts;
    uint64_t sent_pkts;
    uint64_t enqdrop_pkts;
  } dist __rte_cache_aligned;
  int pad2 __rte_cache_aligned;

  struct {
    uint64_t dequeue_pkts;
    uint64_t tx_pkts;
    uint64_t enqdrop_pkts;
  } tx __rte_cache_aligned;
  int pad3 __rte_cache_aligned;

  uint64_t worker_pkts[64] __rte_cache_aligned;

  int pad4 __rte_cache_aligned;

  uint64_t worker_bursts[64][8] __rte_cache_aligned;

  int pad5 __rte_cache_aligned;

  uint64_t port_rx_pkts[64] __rte_cache_aligned;
  uint64_t port_tx_pkts[64] __rte_cache_aligned;
  double *lat[64];
} app_stats;

struct app_stats prev_app_stats;

static const struct rte_eth_conf port_conf_default = {
    .rxmode =
        {
            .mq_mode = RTE_ETH_MQ_RX_RSS,
        },
    .txmode =
        {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
    .rx_adv_conf = {.rss_conf =
                        {
                            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP |
                                      RTE_ETH_RSS_TCP | RTE_ETH_RSS_SCTP,
                        }},
};

struct output_buffer {
  unsigned count;
  struct rte_mbuf *mbufs[BURST_SIZE];
};

static void print_stats(void);

struct lcore_params {
  unsigned worker_id;
  struct rte_distributor *d;
  struct rte_ring *rx_dist_ring;
  struct rte_ring *dist_tx_ring;
  struct rte_mempool *mem_pool;
};

static int lcore_gen(struct lcore_params *p) {
  const uint16_t nb_ports = rte_eth_dev_count_avail();
  struct rte_mbuf *bufs[BURST_SIZE * 2];
  uint64_t tsc;
  char *payload;
  size_t offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                  sizeof(struct rte_udp_hdr);
  uint64_t hz = rte_get_timer_hz();

  RTE_LOG_DP(DEBUG, DISTRAPP, "%s: singlal: %d\n", __func__, quit_signal_rx);

  int rss_cnt = 0;
  while (!quit_signal_rx) {

    // Generate packets
    if (rte_pktmbuf_alloc_bulk(p->mem_pool, bufs, BURST_SIZE) != 0) {
      fprintf(stderr, "Fail to allocate %u mbufs on generate core\n",
              BURST_SIZE);
      return -1;
    }
    for (uint16_t i = 0; i < BURST_SIZE; i++) {
      bufs[i]->hash.rss = rss_cnt++;
    }
    app_stats.rx.rx_pkts += BURST_SIZE;
    // Put time stamp in packets
    tsc = rte_get_timer_cycles();
    for (uint16_t i = 0; i < BURST_SIZE; i++) {
      payload = rte_pktmbuf_mtod_offset(bufs[i], char *, offset);
      rte_memcpy(payload, &tsc, sizeof(tsc));
    }

    /*
     * Swap the following two lines if you want the rx traffic
     * to go directly to tx, no distribution.
     */
    // struct rte_ring *out_ring = p->rx_dist_ring;
    struct rte_ring *out_ring = p->dist_tx_ring;

    uint16_t sent =
        rte_ring_enqueue_burst(out_ring, (void *)bufs, BURST_SIZE, NULL);

    app_stats.rx.enqueued_pkts += sent;
    if (unlikely(sent < BURST_SIZE)) {
      app_stats.rx.enqdrop_pkts += BURST_SIZE - sent;
      RTE_LOG_DP(DEBUG, DISTRAPP, "%s:Packet loss due to full ring\n",
                 __func__);
      while (sent < BURST_SIZE)
        rte_pktmbuf_free(bufs[sent++]);
    }
  }
  printf("\nCore %u exiting rx task.\n", rte_lcore_id());
  /* set distributor threads quit flag */
  quit_signal_dist = 1;
  return 0;
}

// static int lcore_lat(struct lcore_params *p) {
//   struct rte_ring *in_r = p->rx_dist_ring;
//   struct rte_mbuf *bufs[BURST_SIZE * 2];
//   uint64_t tsc;
//   size_t offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)
//   +
//                   sizeof(struct rte_udp_hdr);
//   uint64_t hz = rte_get_timer_hz();
//
//   printf("\nCore %u acting as latency core.\n", rte_lcore_id());
//   while (!quit_signal_rx) {
//     const uint16_t nb_rx =
//         rte_ring_dequeue_burst(in_r, (void *)bufs, BURST_SIZE * 2, NULL);
//     app_stats.tx.dequeue_pkts += nb_rx;
//     for (int i = 0; i < nb_rx; i++) {
//       tsc = rte_get_timer_cycles();
//       char *payload = rte_pktmbuf_mtod_offset(bufs[i], char *, offset);
//       uint64_t tsc_rx;
//       rte_memcpy(&tsc_rx, payload, sizeof(tsc_rx));
//       app_stats.lat = (tsc - tsc_rx) * 1000000.0 / (double)hz;
//       rte_memcpy(payload, &tsc, sizeof(tsc));
//       rte_pktmbuf_free(bufs[i]);
//     }
//   }
//   printf("\nCore %u exiting latency task.\n", rte_lcore_id());
//   /* set distributor threads quit flag */
//   quit_signal_dist = 1;
//   return 0;
// }

static inline void flush_one_port(struct output_buffer *outbuf, uint8_t outp) {
  unsigned int nb_tx = rte_eth_tx_burst(outp, 0, outbuf->mbufs, outbuf->count);
  app_stats.tx.tx_pkts += outbuf->count;

  if (unlikely(nb_tx < outbuf->count)) {
    app_stats.tx.enqdrop_pkts += outbuf->count - nb_tx;
    do {
      rte_pktmbuf_free(outbuf->mbufs[nb_tx]);
    } while (++nb_tx < outbuf->count);
  }
  outbuf->count = 0;
}

static inline void flush_all_ports(struct output_buffer *tx_buffers) {
  uint16_t outp;

  RTE_ETH_FOREACH_DEV(outp) {
    /* skip ports that are not enabled */
    if ((enabled_port_mask & (1 << outp)) == 0)
      continue;

    if (tx_buffers[outp].count == 0)
      continue;

    flush_one_port(&tx_buffers[outp], outp);
  }
}

static int lcore_distributor(struct lcore_params *p) {
  struct rte_ring *in_r = p->rx_dist_ring;
  struct rte_ring *out_r = p->dist_tx_ring;
  struct rte_mbuf *bufs[BURST_SIZE * 4];
  struct rte_distributor *d = p->d;

  printf("\nCore %u acting as distributor core.\n", rte_lcore_id());
  while (!quit_signal_dist) {
    const uint16_t nb_rx =
        rte_ring_dequeue_burst(in_r, (void *)bufs, BURST_SIZE * 1, NULL);
    if (nb_rx) {
      app_stats.dist.in_pkts += nb_rx;

      /* Distribute the packets */
      rte_distributor_process(d, bufs, nb_rx);
      /* Handle Returns */
      const uint16_t nb_ret =
          rte_distributor_returned_pkts(d, bufs, BURST_SIZE * 2);

      if (unlikely(nb_ret == 0))
        continue;
      app_stats.dist.ret_pkts += nb_ret;

      uint16_t sent = rte_ring_enqueue_burst(out_r, (void *)bufs, nb_ret, NULL);
      app_stats.dist.sent_pkts += sent;
      if (unlikely(sent < nb_ret)) {
        app_stats.dist.enqdrop_pkts += nb_ret - sent;
        RTE_LOG(DEBUG, DISTRAPP, "%s:Packet loss due to full out ring\n",
                __func__);
        while (sent < nb_ret)
          rte_pktmbuf_free(bufs[sent++]);
      }
    }
  }
  printf("\nCore %u exiting distributor task.\n", rte_lcore_id());
  /* set tx threads quit flag */
  quit_signal = 1;
  /* set worker threads quit flag */
  quit_signal_work = 1;
  rte_distributor_flush(d);
  /* Unblock any returns so workers can exit */
  rte_distributor_clear_returns(d);
  return 0;
}

static void int_handler(int sig_num) {
  printf("Exiting on signal %d\n", sig_num);
  /* set quit flag for rx thread to exit */
  quit_signal_rx = 1;
}

static void print_stats(void) {
  struct rte_eth_stats eth_stats;
  unsigned int i, j;

  RTE_ETH_FOREACH_DEV(i) {
    rte_eth_stats_get(i, &eth_stats);
    app_stats.port_rx_pkts[i] = eth_stats.ipackets;
    app_stats.port_tx_pkts[i] = eth_stats.opackets;
  }

  printf("\n\nRX Thread:\n");
  RTE_ETH_FOREACH_DEV(i) {
    printf("Port %u Pktsin : %5.2f\n", i,
           (app_stats.port_rx_pkts[i] - prev_app_stats.port_rx_pkts[i]) /
               1000000.0);
    prev_app_stats.port_rx_pkts[i] = app_stats.port_rx_pkts[i];
  }
  printf(" - Received:    %5.2f\n",
         (app_stats.rx.rx_pkts - prev_app_stats.rx.rx_pkts) / 1000000.0);
  printf(" - Returned:    %5.2f\n",
         (app_stats.rx.returned_pkts - prev_app_stats.rx.returned_pkts) /
             1000000.0);
  printf(" - Enqueued:    %5.2f\n",
         (app_stats.rx.enqueued_pkts - prev_app_stats.rx.enqueued_pkts) /
             1000000.0);
  printf(" - Dropped:     %s%5.2f%s\n", ANSI_COLOR_RED,
         (app_stats.rx.enqdrop_pkts - prev_app_stats.rx.enqdrop_pkts) /
             1000000.0,
         ANSI_COLOR_RESET);

  printf("Distributor thread:\n");
  printf(" - In:          %5.2f\n",
         (app_stats.dist.in_pkts - prev_app_stats.dist.in_pkts) / 1000000.0);
  printf(" - Returned:    %5.2f\n",
         (app_stats.dist.ret_pkts - prev_app_stats.dist.ret_pkts) / 1000000.0);
  printf(" - Sent:        %5.2f\n",
         (app_stats.dist.sent_pkts - prev_app_stats.dist.sent_pkts) /
             1000000.0);
  printf(" - Dropped      %s%5.2f%s\n", ANSI_COLOR_RED,
         (app_stats.dist.enqdrop_pkts - prev_app_stats.dist.enqdrop_pkts) /
             1000000.0,
         ANSI_COLOR_RESET);

  printf("TX thread:\n");
  printf(" - Dequeued:    %5.2f\n",
         (app_stats.tx.dequeue_pkts - prev_app_stats.tx.dequeue_pkts) /
             1000000.0);
  RTE_ETH_FOREACH_DEV(i) {
    printf("Port %u Pktsout: %5.2f\n", i,
           (app_stats.port_tx_pkts[i] - prev_app_stats.port_tx_pkts[i]) /
               1000000.0);
    prev_app_stats.port_tx_pkts[i] = app_stats.port_tx_pkts[i];
  }
  printf(" - Transmitted: %5.2f\n",
         (app_stats.tx.tx_pkts - prev_app_stats.tx.tx_pkts) / 1000000.0);
  printf(" - Dropped:     %s%5.2f%s\n", ANSI_COLOR_RED,
         (app_stats.tx.enqdrop_pkts - prev_app_stats.tx.enqdrop_pkts) /
             1000000.0,
         ANSI_COLOR_RESET);
  printf(" - Latency:     %5.2f\n", app_stats.lat[0][iters]);

  prev_app_stats.rx.rx_pkts = app_stats.rx.rx_pkts;
  prev_app_stats.rx.returned_pkts = app_stats.rx.returned_pkts;
  prev_app_stats.rx.enqueued_pkts = app_stats.rx.enqueued_pkts;
  prev_app_stats.rx.enqdrop_pkts = app_stats.rx.enqdrop_pkts;
  prev_app_stats.dist.in_pkts = app_stats.dist.in_pkts;
  prev_app_stats.dist.ret_pkts = app_stats.dist.ret_pkts;
  prev_app_stats.dist.sent_pkts = app_stats.dist.sent_pkts;
  prev_app_stats.dist.enqdrop_pkts = app_stats.dist.enqdrop_pkts;
  prev_app_stats.tx.dequeue_pkts = app_stats.tx.dequeue_pkts;
  prev_app_stats.tx.tx_pkts = app_stats.tx.tx_pkts;
  prev_app_stats.tx.enqdrop_pkts = app_stats.tx.enqdrop_pkts;

  for (i = 0; i < num_workers; i++) {
    printf("Worker %02u Pkts: %5.2f. Bursts(1-8): ", i,
           (app_stats.worker_pkts[i] - prev_app_stats.worker_pkts[i]) /
               1000000.0);
    for (j = 0; j < 8; j++) {
      printf("%" PRIu64 " ", app_stats.worker_bursts[i][j]);
      app_stats.worker_bursts[i][j] = 0;
    }
    printf("\n");
    prev_app_stats.worker_pkts[i] = app_stats.worker_pkts[i];
  }
}

// static int lcore_worker(struct lcore_params *p) {
//   struct rte_distributor *d = p->d;
//   const unsigned id = p->worker_id;
//   unsigned int num = 0;
//   unsigned int i;
//
//   struct rte_mbuf *buf[8] __rte_cache_aligned;
//
//   for (i = 0; i < 8; i++)
//     buf[i] = NULL;
//
//   app_stats.worker_pkts[p->worker_id] = 1;
//
//   printf("\nCore %u acting as worker core.\n", rte_lcore_id());
//   while (!quit_signal_work) {
//     num = rte_distributor_get_pkt(d, id, buf, buf, num);
//     for (i = 0; i < num; i++) {
//       /* swap src and dst */
//       struct rte_ether_hdr *eth_hdr =
//           rte_pktmbuf_mtod(buf[i], struct rte_ether_hdr *);
//     }
//
//     app_stats.worker_pkts[p->worker_id] += num;
//     if (num > 0)
//       app_stats.worker_bursts[p->worker_id][num - 1]++;
//   }
//   rte_free(p);
//   return 0;
//   }

static int lcore_worker(struct lcore_params *p) {
  struct rte_ring *in_r = p->rx_dist_ring;
  struct rte_mbuf *bufs[BURST_SIZE * 2];
  struct rte_distributor *d = p->d;
  const unsigned id = p->worker_id;
  uint64_t tsc = 0;
  size_t offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                  sizeof(struct rte_udp_hdr);
  uint64_t hz = rte_get_timer_hz();
  app_stats.lat[id] = malloc(sizeof(double) * iters);
  int lat_idx = 0;
  int rx_cnt = 0;

  printf("\nCore %u acting as worker core. worker id: %d\n", rte_lcore_id(),
         id);
  while (!quit_signal_work) {
    const uint16_t nb_rx = rte_distributor_get_pkt(d, id, bufs, NULL, 0);
    // app_stats.tx.dequeue_pkts += nb_rx;
    for (int i = 0; i < nb_rx; i++) {
      if (rx_cnt % 1000) {
        tsc = rte_get_timer_cycles();
        char *payload = rte_pktmbuf_mtod_offset(bufs[i], char *, offset);
        uint64_t tsc_rx = 0;
        rte_memcpy(&tsc_rx, payload, sizeof(tsc_rx));
        app_stats.lat[id][(lat_idx++) % iters] =
            (tsc - tsc_rx) * 1000000.0 / (double)hz;
      }
      rx_cnt++;
      rte_pktmbuf_free(bufs[i]);
    }
  }
  printf("\nCore %u exiting worker task.\n", rte_lcore_id());
  rte_free(p);
  /* set distributor threads quit flag */
  quit_signal_dist = 1;
  return 0;
}

static int init_power_library(void) {
  int ret = 0, lcore_id;
  RTE_LCORE_FOREACH_WORKER(lcore_id) {
    /* init power management library */
    ret = rte_power_init(lcore_id);
    if (ret) {
      RTE_LOG(ERR, POWER, "Library initialization failed on core %u\n",
              lcore_id);
      /*
       * Return on first failure, we'll fall back
       * to non-power operation
       */
      return ret;
    }
  }
  return ret;
}

/* display usage */
static void print_usage(const char *prgname) {
  printf("%s [EAL options] -- -p PORTMASK [-c]\n"
         "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
         "  -c: Combines the RX core with the distribution core\n",
         prgname);
}

static int parse_portmask(const char *portmask) {
  char *end = NULL;
  unsigned long pm;

  /* parse hexadecimal string */
  pm = strtoul(portmask, &end, 16);
  if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
    return 0;

  return pm;
}

/* Parse the argument given in the command line of the application */
static int parse_args(int argc, char **argv) {
  int opt;
  char **argvopt;
  int option_index;
  char *prgname = argv[0];
  static struct option lgopts[] = {{NULL, 0, 0, 0}};

  argvopt = argv;
  while ((opt = getopt_long(argc, argvopt, "cp:", lgopts, &option_index)) !=
         EOF) {

    switch (opt) {
    case 'p':
      break;

    case 'c':
      break;

    default:
      print_usage(prgname);
      return -1;
    }
  }

  if (optind <= 1) {
    print_usage(prgname);
    return -1;
  }

  argv[optind - 1] = prgname;

  optind = 1; /* reset getopt lib */
  return 0;
}
// Function to compare two doubles (for qsort)
int compare_doubles(const void *a, const void *b) {
  return (*(double *)a > *(double *)b) - (*(double *)a < *(double *)b);
}

// Function to calculate the p99 value from multiple lists
double calculate_p99(double *combined, int total_size) {
  // Sort the combined array
  qsort(combined, total_size, sizeof(double), compare_doubles);

  // Calculate the index for the p99 value
  int p99_index = (int)(total_size * 0.99); // 99th percentile index
  return combined[p99_index];
}

/* Main function, does initialization and calls the per-lcore functions */
int main(int argc, char *argv[]) {
  struct rte_mempool *mbuf_pool;
  struct rte_distributor *d;
  struct rte_ring *dist_ring, *tx_ring;
  unsigned int lcore_id, worker_id = 0;
  int distr_core_id = -1;
  int gen_core_ids[NUM_PRODUCER_CORES];
  unsigned int min_cores;
  uint64_t t, freq;

  /* catch ctrl-c so we can print on exit */
  signal(SIGINT, int_handler);

  /* init EAL */
  int ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
  argc -= ret;
  argv += ret;

  /* parse application arguments (after the EAL ones) */
  ret = parse_args(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid distributor parameters\n");

  // 8 producer, 1 worker, 1 distributor, 1 reciever, 1 stats
  min_cores = 11;
  num_workers = rte_lcore_count() - 10;

  if (rte_lcore_count() < min_cores)
    rte_exit(EXIT_FAILURE, "Error, This application needs at "
                           "least 4 logical cores to run:\n"
                           "1 lcore for stats (can be core 0)\n"
                           "1 or 2 lcore for packet RX and distribution\n"
                           "1 lcore for packet TX\n"
                           "and at least 1 lcore for worker threads\n");

  mbuf_pool =
      rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

  d = rte_distributor_create("PKT_DIST", rte_socket_id(), num_workers,
                             RTE_DIST_ALG_BURST);
  if (d == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create distributor\n");

  // Ring for generated packets
  dist_ring =
      rte_ring_create("Input_ring", SCHED_RX_RING_SZ, rte_socket_id(), 0);
  if (dist_ring == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create dist ring\n");

  // Ring going to tx
  tx_ring = rte_ring_create("Output_ring", SCHED_RX_RING_SZ, rte_socket_id(),
                            RING_F_SC_DEQ | RING_F_SP_ENQ);
  if (tx_ring == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create output ring\n");

  for (int i = 0; i < NUM_PRODUCER_CORES; i++)
    gen_core_ids[i] = -1;
  /*
   * If there's any of the key workloads left without an lcore_id
   * after the high performing core assignment above, pre-assign
   * them here.
   */
  RTE_LCORE_FOREACH_WORKER(lcore_id) {
    int on_gen_core = 0;
    int set_gen_core = 0;
    for (int i = 0; i < NUM_PRODUCER_CORES; i++) {
      if (gen_core_ids[i] == lcore_id) {
        on_gen_core = 1;
        break;
      }
    }
    if (lcore_id == (unsigned int)distr_core_id || on_gen_core)
      continue;
    for (int i = 0; i < NUM_PRODUCER_CORES; i++) {
      if (gen_core_ids[i] < 0) {
        gen_core_ids[i] = lcore_id;
        set_gen_core = 1;
        printf("Gen on core %d\n", lcore_id);
        break;
      }
    }
    if (set_gen_core)
      continue;
    if (distr_core_id < 0) {
      distr_core_id = lcore_id;
      printf("Distributor on core %d\n", lcore_id);
      continue;
    }
  }

  printf("dist id %d \n", distr_core_id);

  /*
   * Kick off all the worker threads first, avoiding the pre-assigned
   * lcore_ids for tx, rx and distributor workloads.
   */
  RTE_LCORE_FOREACH_WORKER(lcore_id) {
    int on_gen_core = 0;
    for (int i = 0; i < NUM_PRODUCER_CORES; i++) {
      if (gen_core_ids[i] == lcore_id) {
        on_gen_core = 1;
        break;
      }
    }
    if (lcore_id == (unsigned int)distr_core_id || on_gen_core)
      continue;
    printf("Starting thread %d as worker, lcore_id %d\n", worker_id, lcore_id);
    struct lcore_params *p = rte_malloc(NULL, sizeof(*p), 0);
    if (!p)
      rte_panic("malloc failure\n");
    *p = (struct lcore_params){worker_id++, d, NULL, NULL, mbuf_pool};

    rte_eal_remote_launch((lcore_function_t *)lcore_worker, p, lcore_id);
  }

  /* Start distributor core */
  struct lcore_params *pd = NULL;
  pd = rte_malloc(NULL, sizeof(*pd), 0);
  if (!pd)
    rte_panic("malloc failure\n");
  *pd = (struct lcore_params){worker_id++, d, dist_ring, tx_ring, mbuf_pool};
  rte_eal_remote_launch((lcore_function_t *)lcore_distributor, pd,
                        distr_core_id);

  /* Start lat core */
  // struct lcore_params *pl = rte_malloc(NULL, sizeof(*pl), 0);
  // if (!pl)
  //   rte_panic("malloc failure\n");
  // *pl = (struct lcore_params){worker_id++, d, tx_ring, NULL, mbuf_pool};
  // rte_eal_remote_launch((lcore_function_t *)lcore_lat, pl, lat_core_id);

  /* Start gen cores */
  struct lcore_params *pr[NUM_PRODUCER_CORES];
  for (int i = 0; i < NUM_PRODUCER_CORES; i++) {
    pr[i] = rte_malloc(NULL, sizeof(struct lcore_params), 0);
    if (!pr[i])
      rte_panic("malloc failure\n");
    *pr[i] = (struct lcore_params){worker_id++, d, NULL, dist_ring, mbuf_pool};
    rte_eal_remote_launch((lcore_function_t *)lcore_gen, pr[i],
                          gen_core_ids[i]);
  }

  freq = rte_get_timer_hz();
  t = rte_rdtsc() + freq;
  while (!quit_signal) {
    if (t < rte_rdtsc()) {
      print_stats();
      t = rte_rdtsc() + freq;
    }
    usleep(1000);
  }

  // calc p99
  printf("Calculating p99 value...\n");
  double *combined = malloc(sizeof(double) * iters * (num_workers));
  for (int i = 0; i < num_workers; i++) {
    for (int j = 0; j < iters; j++) {
      combined[i * iters + j] = app_stats.lat[i][j];
    }
  }

  double p99 = calculate_p99(combined, iters * num_workers);
  // Print the result
  printf("p99 value: %.2f\n", p99);
  // calc average accross all workers
  double avg = 0;
  for (int i = 0; i < num_workers; i++) {
    double sum = 0;
    for (int j = 0; j < iters; j++) {
      sum += app_stats.lat[i][j];
    }
    avg += sum / iters;
  }
  printf("average latency: %.2f\n", avg / num_workers);
  // free lats
  for (int i = 0; i < num_workers; i++) {
    free(app_stats.lat[i]);
  }
  RTE_LCORE_FOREACH_WORKER(lcore_id) {
    if (rte_eal_wait_lcore(lcore_id) < 0)
      return -1;
  }

  print_stats();

  rte_free(pd);
  for (int i = 0; i < NUM_PRODUCER_CORES; i++)
    rte_free(pr[i]);

  /* clean up the EAL */
  rte_eal_cleanup();

  return 0;
}
