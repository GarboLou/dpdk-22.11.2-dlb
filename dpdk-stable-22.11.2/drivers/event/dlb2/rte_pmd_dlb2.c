/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <rte_eventdev.h>
#include <eventdev_pmd.h>

#include "rte_pmd_dlb2.h"
#include "dlb2_priv.h"
#include "dlb2_inline_fns.h"

int
rte_pmd_dlb2_set_token_pop_mode(uint8_t dev_id,
				uint8_t port_id,
				enum dlb2_token_pop_mode mode)
{
	struct dlb2_eventdev *dlb2;
	struct rte_eventdev *dev;

	RTE_EVENTDEV_VALID_DEVID_OR_ERR_RET(dev_id, -EINVAL);
	dev = &rte_eventdevs[dev_id];

	dlb2 = dlb2_pmd_priv(dev);

	if (mode >= NUM_TOKEN_POP_MODES)
		return -EINVAL;

	/* The event device must be configured, but not yet started */
	if (!dlb2->configured || dlb2->run_state != DLB2_RUN_STATE_STOPPED)
		return -EINVAL;

	/* The token pop mode must be set before configuring the port */
	if (port_id >= dlb2->num_ports || dlb2->ev_ports[port_id].setup_done)
		return -EINVAL;

	if (dlb2->version == DLB2_HW_V2_5 && mode == DELAYED_POP) {
		dlb2->ev_ports[port_id].qm_port.enable_inflight_ctrl = true;
		dlb2->ev_ports[port_id].qm_port.inflight_threshold = 1;
		mode = AUTO_POP;
	}

	dlb2->ev_ports[port_id].qm_port.token_pop_mode = mode;

	return 0;
}

int
rte_pmd_dlb2_set_port_param(uint8_t dev_id,
			    uint8_t port_id,
			    uint64_t flags,
			    void *val)
{
	struct dlb2_eventdev *dlb2;
	struct rte_eventdev *dev;

	if (val == NULL)
		return -EINVAL;

	RTE_EVENTDEV_VALID_DEVID_OR_ERR_RET(dev_id, -EINVAL);
	dev = &rte_eventdevs[dev_id];

	dlb2 = dlb2_pmd_priv(dev);

	if (port_id >= dlb2->num_ports)
		return -EINVAL;

	return dlb2_set_port_param(dlb2, port_id, flags, val);
}
