/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2020 Intel Corporation
 */

#ifndef _DLB2_IOCTL_H_
#define _DLB2_IOCTL_H_

#include <stdbool.h>
#include <stdint.h>
#include <rte_debug.h>
#include <rte_bus_pci.h>
#include <rte_log.h>
#include <rte_dev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_kvargs.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_io.h>
#include <rte_eventdev.h>
#include <eventdev_pmd.h>

#include "../dlb2_priv.h"

/*
 * Note: The following operate on device_id, rather than domain_id:
 * 1) dlb2_ioctl_get_device_version
 * 2) dlb2_ioctl_sched_domain_create
 * 3) dlb2_ioctl_get_num_resources
 */
int dlb2_ioctl_get_device_version(struct dlb2_hw_dev *handle,
				  uint8_t *revision,
				  uint8_t *version);
int dlb2_ioctl_get_num_resources(struct dlb2_hw_dev *handle,
				 struct dlb2_get_num_resources_args *rsrcs);
int dlb2_ioctl_sched_domain_create(struct dlb2_hw_dev *handle,
				   struct dlb2_create_sched_domain_args *args);
int dlb2_ioctl_ldb_queue_create(struct dlb2_hw_dev *handle,
				struct dlb2_create_ldb_queue_args *cfg);
int dlb2_ioctl_dir_queue_create(struct dlb2_hw_dev *handle,
				struct dlb2_create_dir_queue_args *cfg);
int dlb2_ioctl_ldb_port_create(struct dlb2_hw_dev *handle,
			       struct dlb2_create_ldb_port_args *cfg,
			       enum dlb2_cq_poll_modes poll_mode,
			       uint8_t evdev_id);
int dlb2_ioctl_dir_port_create(struct dlb2_hw_dev *handle,
			       struct dlb2_create_dir_port_args *cfg,
			       enum dlb2_cq_poll_modes poll_mode,
			       uint8_t evdev_id);
int dlb2_ioctl_map_qid(struct dlb2_hw_dev *handle,
		       struct dlb2_map_qid_args *cfg);
int dlb2_ioctl_unmap_qid(struct dlb2_hw_dev *handle,
			 struct dlb2_unmap_qid_args *cfg);
int dlb2_ioctl_sched_domain_start(struct dlb2_hw_dev *handle,
				  struct dlb2_start_domain_args *cfg);
int dlb2_ioctl_sched_domain_stop(struct dlb2_hw_dev *handle,
				 struct dlb2_stop_domain_args *cfg);
int dlb2_ioctl_block_on_cq_interrupt(struct dlb2_hw_dev *handle,
				     int port_id,
				     bool is_ldb,
				     volatile void *cq_va,
				     uint8_t cq_gen,
				     bool arm);
int dlb2_ioctl_pending_port_unmaps(struct dlb2_hw_dev *handle,
				   struct dlb2_pending_port_unmaps_args *args);
int dlb2_ioctl_get_ldb_queue_depth(struct dlb2_hw_dev *handle,
				   struct dlb2_get_ldb_queue_depth_args *args);
int dlb2_ioctl_get_dir_queue_depth(struct dlb2_hw_dev *handle,
				   struct dlb2_get_dir_queue_depth_args *args);
#endif /* _DLB2_IOCTL_H_ */
