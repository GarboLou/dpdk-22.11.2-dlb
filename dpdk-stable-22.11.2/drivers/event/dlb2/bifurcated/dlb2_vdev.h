/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2020 Intel Corporation
 */

#ifndef _DLB2_VDEV_H_
#define _DLB2_VDEV_H_

/* vdev specific functions */
int dlb2_register_pri_mp_callbacks(void);
int dlb2_register_sec_mp_callbacks(void);

extern struct
process_local_port_data dlb2_port[RTE_EVENT_MAX_DEVS]
				 [DLB2_MAX_NUM_PORTS_ALL]
				 [DLB2_NUM_PORT_TYPES];

extern int eal_parse_sysfs_value(const char *filename, unsigned long *val);

#endif /* _DLB2_VDEV_H_ */
