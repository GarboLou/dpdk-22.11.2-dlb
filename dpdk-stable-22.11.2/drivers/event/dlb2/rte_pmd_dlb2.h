/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

/*!
 *  @file      rte_pmd_dlb2.h
 *
 *  @brief     DLB PMD-specific functions
 */

#ifndef _RTE_PMD_DLB2_H_
#define _RTE_PMD_DLB2_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/**
 * Macros to get/set QID depth and QE weight from rte_event metadata.
 * Currently 'rsvd' field is used for these. Lower 2 bits are used to store
 * QID depth while the upper 2 bits are used for QER weight.
 */
#define DLB2_GET_QID_DEPTH(x) ((x)->rsvd & 0x3)
#define DLB2_SET_QID_DEPTH(x, v) ((x)->rsvd = ((x)->rsvd & ~0x3) | (v & 0x3))
#define DLB2_GET_QE_WEIGHT(x) (((x)->rsvd >> 2) & 0x3)
#define DLB2_SET_QE_WEIGHT(x, v) ((x)->rsvd = ((x)->rsvd & 0x3) | ((v & 0x3) << 2))

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Selects the token pop mode for a DLB2 port.
 */
enum dlb2_token_pop_mode {
	/* Pop the CQ tokens immediately after dequeueing. */
	AUTO_POP,
	/* Pop CQ tokens after (dequeue_depth - 1) events are released.
	 * Supported on load-balanced ports only.
	 */
	DELAYED_POP,
	/* Pop the CQ tokens during next dequeue operation. */
	DEFERRED_POP,

	/* NUM_TOKEN_POP_MODES must be last */
	NUM_TOKEN_POP_MODES
};

/*!
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Configure the token pop mode for a DLB2 port. By default, all ports use
 * AUTO_POP. This function must be called before calling rte_event_port_setup()
 * for the port, but after calling rte_event_dev_configure().
 *
 * @param dev_id
 *    The identifier of the event device.
 * @param port_id
 *    The identifier of the event port.
 * @param mode
 *    The token pop mode.
 *
 * @return
 * - 0: Success
 * - EINVAL: Invalid dev_id, port_id, or mode
 * - EINVAL: The DLB2 is not configured, is already running, or the port is
 *   already setup
 */

__rte_experimental
int
rte_pmd_dlb2_set_token_pop_mode(uint8_t dev_id,
				uint8_t port_id,
				enum dlb2_token_pop_mode mode);

/** Set inflight threshold for flow migration */
#define DLB2_FLOW_MIGRATION_THRESHOLD RTE_BIT64(0)

/** Set port history list */
#define DLB2_SET_PORT_HL RTE_BIT64(1)

struct dlb2_port_param {
	uint16_t inflight_threshold : 12;
	uint16_t port_hl;
};

/*!
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Configure various port parameters.
 * AUTO_POP. This function must be called before calling rte_event_port_setup()
 * for the port, but after calling rte_event_dev_configure().
 *
 * @param dev_id
 *    The identifier of the event device.
 * @param port_id
 *    The identifier of the event port.
 * @param flags
 *    Bitmask of the parameters being set.
 * @param val
 *    Structure coantaining the values of parameters being set.
 *
 * @return
 * - 0: Success
 * - EINVAL: Invalid dev_id, port_id, or mode
 * - EINVAL: The DLB2 is not configured, is already running, or the port is
 *   already setup
 */
__rte_experimental
int
rte_pmd_dlb2_set_port_param(uint8_t dev_id,
			    uint8_t port_id,
			    uint64_t flags,
			    void *val);
#ifdef __cplusplus
}
#endif

#endif /* _RTE_PMD_DLB2_H_ */
