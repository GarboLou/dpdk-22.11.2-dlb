/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2020 Intel Corporation
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <dirent.h>

#include <rte_debug.h>
#include <rte_bus_vdev.h>
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
#include <eventdev_pmd_vdev.h>
#include <rte_string_fns.h>
#include "bus_pci_driver.h"

#include "dlb2_ioctl.h"
#include "../dlb2_priv.h"
#include "../dlb2_iface.h"
#include "dlb2_vdev.h"
#include "../dlb2_inline_fns.h"

#if !defined RTE_ARCH_X86_64
#error "This implementation only supports RTE_ARCH_X86_64 architecture."
#endif

/*
 * Process-local globals are required for multiprocess support.
 * Note that a single process could potentially have more than one DLB2
 * device/domain open, thus the extra array dimension.
 */

static int dlb2_device_fd[RTE_EVENT_MAX_DEVS];
static rte_spinlock_t dlb2_domain_fd_lock;
static int dlb2_domain_fd[RTE_EVENT_MAX_DEVS][DLB2_MAX_NUM_DOMAINS];
static bool ll_init_done;

static volatile bool eventdev_reset_all_comms_complete;

/* RTE MP IPC strings */
#define DLB2_MP_SECONDARY_RESET_REQUEST "dlb2_mp_secondary_reset_request"
#define DLB2_MP_DO_RESET "dlb2_mp_do_reset"
#define DLB2_MP_RESET_COMPLETE "dlb2_mp_reset_complete"
#define DLB2_MP_DOMAIN_FD_REQUEST "dlb2_mp_domain_fd_request"
#define DLB2_MP_DOMAIN_FD_PUBLISH "dlb2_mp_domain_fd_publish"

#define PCI_DEVICE_ID_INTEL_DLB2_PF 0x2710
#define PCI_DEVICE_ID_INTEL_DLB2_VF 0x2711
#define PCI_DEVICE_ID_INTEL_DLB2_5_PF 0x2714
#define PCI_DEVICE_ID_INTEL_DLB2_5_VF 0x2715
#define PCI_VENDOR_ID_INTEL 0x8086

static int
dlb2_send_mp_sync_request(const char *msg_string,
			  void *param,
			  size_t len_param,
			  int fd,
			  struct rte_mp_reply *mp_reply);

static int
dlb2_get_sched_domain_fd(struct dlb2_hw_dev *handle)
{
	struct rte_mp_reply mp_reply;
	int fd, ret;
	uint8_t id[2];

	id[0] = handle->domain_id;
	id[1] = handle->device_id;

	ret = dlb2_send_mp_sync_request(DLB2_MP_DOMAIN_FD_REQUEST,
					&id, sizeof(id), -1, &mp_reply);
	if (ret)
		return ret;

	fd = mp_reply.msgs[0].fds[0];

	free(mp_reply.msgs);

	return fd;
}

static int
dlb2_domain_open(struct dlb2_hw_dev *handle)
{
	int fd, ret = 0;

	rte_spinlock_lock(&dlb2_domain_fd_lock);

	if (!handle->domain_id_valid) {
		DLB2_LOG_ERR("domain not created yet\n");
		ret = -EINVAL;
		goto cleanup;
	}

	/* Do nothing if already open? */
	if (dlb2_domain_fd[handle->device_id][handle->domain_id] < 0) {
		DLB2_LOG_DBG("Open DLB2 domain %u\n", handle->domain_id);

		fd = dlb2_get_sched_domain_fd(handle);
		if (fd < 0) {
			ret = fd;
			DLB2_LOG_ERR("open failed: domain %u (ret: %d)\n",
				     handle->domain_id, ret);
			goto cleanup;
		}

		dlb2_domain_fd[handle->device_id][handle->domain_id] = fd;
	}
#ifdef DLB2_DEBUG
	else
		DLB2_LOG_DBG("domain file %s already open\n",
			     handle->domain_device_path);
#endif

cleanup:
	rte_spinlock_unlock(&dlb2_domain_fd_lock);

	return ret;
}

static int
dlb2_ioctl_get_cq_poll_mode(struct dlb2_hw_dev *handle,
			    enum dlb2_cq_poll_modes *mode)
{
	struct dlb2_query_cq_poll_mode_args args = {0};
	int ret;

	ret = ioctl(dlb2_device_fd[handle->device_id],
		    DLB2_IOC_QUERY_CQ_POLL_MODE,
		    (unsigned long)&args);

	*mode = args.response.id;

	return (ret != 0) ? -errno : 0;
}

static void
dlb2_ioctl_hardware_init(struct dlb2_hw_dev *handle)
{
	RTE_SET_USED(handle);

	/* Intentionally left blank. Only pf pmd inits hw */
}

static int dlb2_ioctl_get_ldb_port_pp_fd(int fd, int port_id);
static int dlb2_ioctl_get_ldb_port_cq_fd(int fd, int port_id);
static int dlb2_ioctl_get_dir_port_pp_fd(int fd, int port_id);
static int dlb2_ioctl_get_dir_port_cq_fd(int fd, int port_id);

static int
dlb2_map_cq(struct dlb2_port *qm_port)
{
	int ret, fd, domain_fd;
	void *mmap_addr;

	if (qm_port->config_state != DLB2_CONFIGURED) {
		DLB2_LOG_ERR("port %d not set up\n", qm_port->id);
		return -EINVAL;
	}

	if (dlb2_port[qm_port->evdev_id][qm_port->id]
		     [PORT_TYPE(qm_port)].cq_base != NULL)
		return 0; /* already mapped */

	ret = dlb2_domain_open(&qm_port->dlb2->qm_instance);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}

	domain_fd = dlb2_domain_fd[qm_port->dlb2->qm_instance.device_id]
				  [qm_port->dlb2->qm_instance.domain_id];

	if (PORT_TYPE(qm_port) == DLB2_LDB_PORT)
		fd = dlb2_ioctl_get_ldb_port_cq_fd(domain_fd, qm_port->id);
	else
		fd = dlb2_ioctl_get_dir_port_cq_fd(domain_fd, qm_port->id);

	if (fd < 0) {
		DLB2_LOG_ERR("dlb2: open port %u's CQ file failed (ret: %d)\n",
			     qm_port->id, fd);
		return fd;
	}

	mmap_addr = mmap(NULL, DLB2_CQ_SIZE, PROT_WRITE, MAP_SHARED, fd, 0);


	if (mmap_addr == (void *)-1) {
		perror("mmap(): ");
		close(fd);
		return -errno;
	}

	if (close(fd) < 0)
		DLB2_LOG_ERR("close port fd %d failed with error = %d\n",
			     fd, errno);

	DLB2_LOG_DBG("mmap OK for port %d, addr=%p\n",
		     qm_port->id, mmap_addr);

	dlb2_port[qm_port->evdev_id][qm_port->id]
		 [PORT_TYPE(qm_port)].cq_base = mmap_addr;
	return 0;
}

static int
dlb2_map_pp(struct dlb2_port *qm_port)
{
	int ret, fd, domain_fd;
	uint64_t *mmap_addr;
	struct process_local_port_data *port_data;

	if (qm_port->config_state != DLB2_CONFIGURED) {
		DLB2_LOG_ERR("port_%d not set up\n",
			     qm_port->id);
		return -EINVAL;
	}
	if (dlb2_port[qm_port->evdev_id][qm_port->id]
		     [PORT_TYPE(qm_port)].pp_addr != NULL)
		return 0; /* already mapped */
	ret = dlb2_domain_open(&qm_port->dlb2->qm_instance);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}
	domain_fd = dlb2_domain_fd[qm_port->dlb2->qm_instance.device_id]
				  [qm_port->dlb2->qm_instance.domain_id];

	if (PORT_TYPE(qm_port) == DLB2_LDB_PORT)
		fd = dlb2_ioctl_get_ldb_port_pp_fd(domain_fd, qm_port->id);
	else
		fd = dlb2_ioctl_get_dir_port_pp_fd(domain_fd, qm_port->id);

	if (fd < 0) {
		DLB2_LOG_ERR("dlb2: open port %u's PP file failed (ret: %d)\n",
			     qm_port->id, fd);
		return fd;
	}
	mmap_addr = mmap(NULL, DLB2_PP_SIZE, PROT_WRITE, MAP_SHARED, fd, 0);

	if (mmap_addr == (void *)-1) {
		perror("mmap(): ");
		close(fd);
		return -errno;
	}

	if (close(fd) < 0) {
		DLB2_LOG_ERR("close port fd %d failed with error = %d\n",
			     fd, errno);
	}

	DLB2_LOG_DBG("mmap OK for port %d, addr=%p\n",
		     qm_port->id, mmap_addr);

	port_data = &dlb2_port[qm_port->evdev_id][qm_port->id]
			      [PORT_TYPE(qm_port)];
	port_data->pp_addr = port_data->autopop_addr = mmap_addr;

	if (port_data->use_ded_autopop_cl)
		port_data->autopop_addr += DLB2_NUM_BYTES_PER_CACHE_LINE;

	return 0;
}

static void
dlb2_mmap_all(struct dlb2_port *qm_port)
{
	struct process_local_port_data *port_data;
	struct dlb2_eventdev *dlb2;

	if (!qm_port)
		rte_panic("%s called with NULL port pointer\n", __func__);

	dlb2 = qm_port->dlb2;

	port_data = &dlb2_port[qm_port->evdev_id][qm_port->id]
			      [PORT_TYPE(qm_port)];

	rte_spinlock_lock(&dlb2->qm_instance.resource_lock);

	if (dlb2_map_pp(qm_port))
		rte_panic("%s could not map producer port for port_%d\n",
			  __func__, qm_port->id);

	if (dlb2_map_cq(qm_port))
		rte_panic("%s could not map consumer queue for port_%d\n",
			  __func__, qm_port->id);

	rte_spinlock_unlock(&dlb2->qm_instance.resource_lock);

	port_data->mmaped = true;
}

/* Setup low level port io just-in-time mmap jhooks. */
static void
dlb2_low_level_io_init(void)
{
	int i, j, evdev_id;

	if (ll_init_done)
		return;

	/* init process-local just-in-time (JIT) memory mapping array */
	for (evdev_id = 0; evdev_id < RTE_EVENT_MAX_DEVS; evdev_id++) {
		for (i = 0; i < DLB2_MAX_NUM_PORTS_ALL; i++) {
			for (j = 0; j < DLB2_NUM_PORT_TYPES; j++) {
				dlb2_port[evdev_id][i][j].pp_addr = NULL;
				dlb2_port[evdev_id][i][j].cq_base = NULL;
			}
		}
	}

	/* init domain fd array to -1 (invalid fd) */

	for (evdev_id = 0; evdev_id < RTE_EVENT_MAX_DEVS; evdev_id++) {
		for (i = 0; i < DLB2_MAX_NUM_DOMAINS; i++)
			dlb2_domain_fd[evdev_id][i] = -1;
	}

	/* init device fd array to -1 (invalid fd) */

	for (evdev_id = 0; evdev_id < RTE_EVENT_MAX_DEVS; evdev_id++)
		dlb2_device_fd[evdev_id] = -1;

	ll_init_done = true;
}

static void
dlb2_unmap_producer_port(struct process_local_port_data *dlb2_port)
{
	if (dlb2_port->pp_addr) {
		if (munmap(dlb2_port->pp_addr, DLB2_PP_SIZE) < 0) {
			DLB2_LOG_ERR("munmap of pp mem failed, errno = %d\n",
				     errno);
		}
	}

	dlb2_port->pp_addr = NULL;
}

static void
dlb2_unmap_cq(struct process_local_port_data *dlb2_port)
{
	if (dlb2_port->cq_base) {
		if (munmap(dlb2_port->cq_base, DLB2_CQ_SIZE) < 0) {
			DLB2_LOG_ERR("munmap of CQ mem failed, errno = %d\n",
				     errno);
		}
	}

	dlb2_port->cq_base = NULL;
}

static void
dlb2_unmap_all(struct dlb2_eventdev *dlb2)
{
	int i;

	/* Unmap PPs and CQ memory memory */
	for (i = 0; i < dlb2->num_ports; i++) {
		struct process_local_port_data *port_data;
		struct dlb2_port *qm_port;

		qm_port = &dlb2->ev_ports[i].qm_port;

		port_data = &dlb2_port[qm_port->evdev_id][qm_port->id]
				      [PORT_TYPE(qm_port)];

		dlb2_unmap_cq(port_data);
		dlb2_unmap_producer_port(port_data);

		port_data->mmaped = false;
	}
}
/* VDEV requires multiprocess communication */

static inline struct dlb2_eventdev *
dlb2_mp_msg_to_dlb2_ptr(const struct rte_mp_msg *msg)
{
	/* cast away const qualifier */
	return *(struct dlb2_eventdev **)(uintptr_t)msg->param;
}

#define DLB2_MP_SYNC_TIMEOUT 10
static int
dlb2_send_mp_sync_request(const char *msg_string,
			  void *param,
			  size_t len_param,
			  int fd,
			  struct rte_mp_reply *mp_reply)
{
	struct rte_mp_msg msg;
	struct timespec ts;
	int ret;

	rte_strlcpy(msg.name, msg_string, RTE_MP_MAX_NAME_LEN);

	msg.num_fds = (fd == -1) ? 0 : 1;
	msg.fds[0] = fd;
	msg.len_param = len_param;

	if (len_param > RTE_MP_MAX_PARAM_LEN)
		return -EINVAL;

	memcpy(msg.param, param, len_param);

	ts.tv_sec = DLB2_MP_SYNC_TIMEOUT;
	ts.tv_nsec = 0;

	ret = rte_mp_request_sync(&msg, mp_reply, &ts);
	if (ret < 0) {
		DLB2_LOG_ERR("rte_mp_sendmsg rte_errno = %d\n",
			     rte_errno);
		ret = -rte_errno;
	}

	return ret;
}

static void
dlb2_domain_close(struct dlb2_hw_dev *handle)
{
	/* Close domain FD */
	rte_spinlock_lock(&dlb2_domain_fd_lock);
	if (dlb2_domain_fd[handle->device_id][handle->domain_id] != -1) {
		if (close(dlb2_domain_fd[handle->device_id]
					[handle->domain_id]) < 0) {
			DLB2_LOG_ERR("close domain %d failed with error = %d\n",
				     handle->domain_id, errno);
		}
		dlb2_domain_fd[handle->device_id][handle->domain_id] = -1;
	}
	rte_spinlock_unlock(&dlb2_domain_fd_lock);
}

/* This temporary thread handles the case where a secondary process requested
 * the domain reset.
 */
static void *
__pri_reset_ctl_fn(void *__args)
{
	struct dlb2_eventdev *dlb2 = __args;
	struct rte_mp_reply mp_reply;
	int ret;

	/* Notify all secondaries that RESET processing is commencing, and wait
	 * for a response to ensure that they have all seen and acted on the
	 * message. Upon successful return from the sync request, all
	 * secondaries will have unmapped their mappings and closed their
	 * domain file descriptors.
	 */
	ret = dlb2_send_mp_sync_request(DLB2_MP_DO_RESET,
					&dlb2, sizeof(dlb2), -1, &mp_reply);
	if (ret)
		rte_panic("%s: send mp_sync DLB2_MP_DO_RESET rte_errno=%d\n",
			  __func__, rte_errno);

	free(mp_reply.msgs);

	/* Unmap all the eventdev's MMIO regions */
	dlb2_unmap_all(dlb2);

	/* Close the process's domain fd */
	dlb2_domain_close(&dlb2->qm_instance);

	/* Close processing is complete! */
	ret = dlb2_send_mp_sync_request(DLB2_MP_RESET_COMPLETE,
					&dlb2, sizeof(dlb2), -1, &mp_reply);
	if (ret)
		rte_panic("%s: mp_sync DLB2_MP_RESET_COMPLETE rte_errno=%d\n",
			  __func__, rte_errno);

	free(mp_reply.msgs);

	return NULL;
}

/* This callback is executed on the primary when a secondary calls
 * dlb2_iface_domain_reset(). The primary then notifies all secondaries that
 * RESET has been requested.
 */
static int
dlb2_secondary_reset_request_cb(const struct rte_mp_msg *msg, const void *peer)
{
	struct dlb2_eventdev *dlb2 = dlb2_mp_msg_to_dlb2_ptr(msg);
	struct rte_mp_msg mp_resp;
	int ret;
	pthread_t pri_reset_ctl_thread;

	/* ACK the mp ipc msg */

	rte_strlcpy(mp_resp.name, msg->name, RTE_MP_MAX_NAME_LEN);

	mp_resp.len_param = 0;
	mp_resp.num_fds = 0;
	if (rte_mp_reply(&mp_resp, peer) < 0) {
		DLB2_LOG_ERR("failed to send mp reply, rte_errno=%d\n",
			     rte_errno);
		return -rte_errno;
	}

	/* Spin off a short lived thread that handles the primary process
	 * actions of a secondary-requested reset. The thread will exit
	 * upon completion of this request.
	 */
	ret = pthread_create(&pri_reset_ctl_thread, NULL,
			     __pri_reset_ctl_fn, (void *)dlb2);
	if (ret)
		rte_panic("Could not create primary reset_ctl thread, err=%d\n",
			  ret);
	return 0;
}

/* This callback is executed on the primary when a secondary calls
 * dlb2_get_sched_domain_fd(). The primary then responds with the scheduling
 * domain fd.
 */
static int
dlb2_domain_fd_request_cb(const struct rte_mp_msg *msg, const void *peer)
{
	struct rte_mp_msg mp_resp;
	uint8_t domain_id;
	uint8_t device_id;

	if (msg->num_fds != 0 || msg->len_param != 2)
		return -EINVAL;

	domain_id = msg->param[0];
	device_id = msg->param[1];

	if (domain_id >= DLB2_MAX_NUM_DOMAINS) {
		DLB2_LOG_ERR("Invalid secondary-requested domain %u\n",
			     domain_id);
		return -EINVAL;
	}

	rte_strlcpy(mp_resp.name, msg->name, RTE_MP_MAX_NAME_LEN);

	mp_resp.len_param = 0;
	mp_resp.num_fds = 1;

	rte_spinlock_lock(&dlb2_domain_fd_lock);

	mp_resp.fds[0] = dlb2_domain_fd[device_id][domain_id];

	rte_spinlock_unlock(&dlb2_domain_fd_lock);

	if (rte_mp_reply(&mp_resp, peer) < 0) {
		DLB2_LOG_ERR("failed to send mp reply, rte_errno=%d\n",
			     rte_errno);
		return -rte_errno;
	}

	return 0;
}

/* This callback is executed on the primary when a secondary calls
 * dlb2_ioctl_sched_domain_create().
 */
static int
dlb2_domain_fd_publish_cb(const struct rte_mp_msg *msg, const void *peer)
{
	struct rte_mp_msg mp_resp;
	uint8_t domain_id, device_id;

	if (msg->num_fds != 1 || msg->len_param != 2)
		return -EINVAL;

	domain_id = msg->param[0];
	device_id = msg->param[1];

	if (domain_id >= DLB2_MAX_NUM_DOMAINS) {
		DLB2_LOG_ERR("Invalid secondary-published domain %u\n",
			     domain_id);
		return -EINVAL;
	}

	rte_spinlock_lock(&dlb2_domain_fd_lock);

	dlb2_domain_fd[device_id][domain_id] = msg->fds[0];

	rte_spinlock_unlock(&dlb2_domain_fd_lock);

	rte_strlcpy(mp_resp.name, msg->name, RTE_MP_MAX_NAME_LEN);

	mp_resp.len_param = 0;
	mp_resp.num_fds = 0;

	if (rte_mp_reply(&mp_resp, peer) < 0) {
		DLB2_LOG_ERR("failed to send mp reply, rte_errno=%d\n",
			     rte_errno);
		return -rte_errno;
	}

	return 0;
}

/* This callback is executed on secondary processes. */
static int
dlb2_do_reset_cb(const struct rte_mp_msg *msg, const void *peer)
{
	struct dlb2_eventdev *dlb2 = dlb2_mp_msg_to_dlb2_ptr(msg);
	struct rte_mp_msg mp_resp;

	/* Do our reset related work before replying */
	dlb2_unmap_all(dlb2);

	dlb2_domain_close(&dlb2->qm_instance);

	/* ACK the mp ipc msg */
	rte_strlcpy(mp_resp.name, msg->name, RTE_MP_MAX_NAME_LEN);

	mp_resp.len_param = 0;
	mp_resp.num_fds = 0;
	if (rte_mp_reply(&mp_resp, peer) < 0) {
		DLB2_LOG_ERR("failed to send mp reply, rte_errno=%d\n",
			     rte_errno);
		return -rte_errno;
	}

	return 0;
}

/* This callback is executed on secondary processes */
static int
dlb2_reset_complete_cb(const struct rte_mp_msg *msg, const void *peer)
{
	struct rte_mp_msg mp_resp;

	/* ACK the mp ipc msg */

	rte_strlcpy(mp_resp.name, msg->name, RTE_MP_MAX_NAME_LEN);

	mp_resp.len_param = 0;
	mp_resp.num_fds = 0;
	if (rte_mp_reply(&mp_resp, peer) < 0) {
		DLB2_LOG_ERR("failed to send mp reply, rte_errno=%d\n",
			     rte_errno);
		return -rte_errno;
	}

	eventdev_reset_all_comms_complete = true;

	return 0;
}

static void
dlb2_do_secondary_initiated_reset(struct dlb2_eventdev *dlb2)
{
	struct timespec endtime, currtime;
	struct rte_mp_reply mp_reply;
	int ret;

	eventdev_reset_all_comms_complete = false; /* clear flag */

	ret = dlb2_send_mp_sync_request(DLB2_MP_SECONDARY_RESET_REQUEST,
					&dlb2, sizeof(dlb2), -1, &mp_reply);
	if (ret)
		rte_panic("%s: DLB2_MP_SECONDARY_RESET_REQUEST err=%d\n",
			  __func__, ret);

	free(mp_reply.msgs);

	/* Wait ~10S for primary-controlled reset to fully complete */
	if (clock_gettime(CLOCK_MONOTONIC, &endtime))
		rte_panic("%s: clock_gettime() failed  err=%d\n",
			  __func__, errno);

	endtime.tv_sec += 10;

	while (!eventdev_reset_all_comms_complete) {
		if (clock_gettime(CLOCK_MONOTONIC, &currtime))
			rte_panic("%s: clock_gettime() failed  err=%d\n",
			  __func__, errno);

		if (currtime.tv_sec >= endtime.tv_sec) {
			rte_panic("%s: Secondary initiated reset timeout\n",
				  __func__);
		}
		rte_pause();
	}
}

static int
dlb2_device_reset(struct dlb2_eventdev *dlb2)
{
	struct rte_mp_reply mp_reply;
	int ret;

	if (dlb2->run_state != DLB2_RUN_STATE_STOPPED) {
		DLB2_LOG_ERR("Internal error: bad state %d for %s\n",
			     (int)dlb2->run_state, __func__);
		return DLB2_ST_DOMAIN_IN_USE;
	}

	/* Make sure domain is open - NOOP if already open */
	ret = dlb2_domain_open(&dlb2->qm_instance);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		/* dlb2_iface_domain_reset called by *secondary* process.
		 * Primary will forward request to other secondaries.
		 */

		dlb2_do_secondary_initiated_reset(dlb2);
		return 0;
	}

	/* dlb2_iface_domain_reset called by *primary* process.
	 * Notify all secondaries that RESET processing is commencing, and wait
	 * for a response to ensure that they have all seen and acted on the
	 * message.
	 */
	ret = dlb2_send_mp_sync_request(DLB2_MP_DO_RESET,
					&dlb2, sizeof(dlb2), -1, &mp_reply);
	if (ret)
		rte_panic("%s: primary shut down event dev, err=%d\n",
			  __func__, ret);

	free(mp_reply.msgs);

	/* Unmap all the eventdev's MMIO regions */
	dlb2_unmap_all(dlb2);

	/* Close the primary process's domain fd */
	dlb2_domain_close(&dlb2->qm_instance);

	/* Notify any secondaries that RESET processing is complete. */
	ret = dlb2_send_mp_sync_request(DLB2_MP_RESET_COMPLETE,
					&dlb2, sizeof(dlb2), -1, &mp_reply);
	if (ret)
		rte_panic("%s: DLB2_MP_RESET_COMPLETE err=%d\n",
			  __func__, ret);

	free(mp_reply.msgs);

	return 0;
}

int
dlb2_register_pri_mp_callbacks(void)
{
	int ret;

	ret = rte_mp_action_register(DLB2_MP_SECONDARY_RESET_REQUEST,
				     dlb2_secondary_reset_request_cb);
	if (ret && rte_errno != EEXIST)
		return -rte_errno;

	ret = rte_mp_action_register(DLB2_MP_DOMAIN_FD_REQUEST,
				     dlb2_domain_fd_request_cb);
	if (ret && rte_errno != EEXIST)
		return -rte_errno;

	ret = rte_mp_action_register(DLB2_MP_DOMAIN_FD_PUBLISH,
				     dlb2_domain_fd_publish_cb);
	if (ret && rte_errno != EEXIST)
		return -rte_errno;

	return 0;
}

int
dlb2_register_sec_mp_callbacks(void)
{
	int ret;

	ret = rte_mp_action_register(DLB2_MP_DO_RESET,
				     dlb2_do_reset_cb);
	if (ret && rte_errno != EEXIST)
		return -rte_errno;

	ret = rte_mp_action_register(DLB2_MP_RESET_COMPLETE,
				     dlb2_reset_complete_cb);
	if (ret && rte_errno != EEXIST)
		goto dlb2_reset_complete_cb_failed;

	return 0;

dlb2_reset_complete_cb_failed:
	rte_mp_action_unregister(DLB2_MP_DO_RESET);

	return -rte_errno;
}

static int
dlb2_get_pmu_type(int dlb_id)
{
	char path[PATH_MAX];
	unsigned long pmu_type;

	snprintf(path, sizeof(path),
		 EVENT_SOURCE_DEV_PATH "%d/type", dlb_id);

	if (eal_parse_sysfs_value(path, &pmu_type) < 0)
		return -1;

	return pmu_type;
}

static int
dlb2_read_perf_sched_idle_counts(int pmu_type,
                                 struct dlb2_sched_idle_counts *data)
{
	uint64_t counter_id[DLB2_MAX_NUM_CNTRS] = {0};
	int fd[DLB2_MAX_NUM_CNTRS], ret;
	struct perf_event_attr attr;
	struct read_format *rf;
	uint64_t index, val;
	char buf[4096];
	uint8_t i;

	rf = (struct read_format *) buf;
	memset(&attr, 0, sizeof(struct perf_event_attr));

	/* First counter is designated as perf events group leader
	 * and its file descriptor is passed in perf_event_open()
	 * syscall of remaining counters.
	 */
	attr.type = pmu_type;
	attr.size = sizeof(struct perf_event_attr);
	/* Event group requires group leader starting counter in
	 * disabled state. Child events must set disabled bit as 0.
	 */
	attr.disabled = 1;
	attr.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID;
	attr.exclude_kernel = 0;
	attr.exclude_hv = 0;
	attr.config = 0; /* First counter == group leader */
	fd[0] = syscall(__NR_perf_event_open, &attr, -1, 0, -1, 0);
	ret = ioctl(fd[0], PERF_EVENT_IOC_ID, &counter_id[0]);
	if (ret != 0) {
		DLB2_LOG_ERR("dlb2: perf grp event id ioctl error\n");
		return -errno;
	}

	/* Remaining counters (child events) */
	for (i = 1; i < DLB2_MAX_NUM_CNTRS; i++) {
		attr.disabled = 0;
		attr.config = i;
		fd[i] = syscall(__NR_perf_event_open, &attr, -1, 0,
				fd[0], 0);
		ret = ioctl(fd[i], PERF_EVENT_IOC_ID, &counter_id[i]);
		if (ret != 0) {
			DLB2_LOG_ERR("dlb2: perf event id ioctl error\n");
			return -errno;
		}
	}

	/* Reset and enable the counters */
	ret = ioctl(fd[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
	if (ret != 0) {
		DLB2_LOG_ERR("dlb2: perf reset ioctl error\n");
		return -errno;
	}
	ret = ioctl(fd[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
	if (ret != 0) {
		DLB2_LOG_ERR("dlb2: perf enable ioctl error\n");
		return -errno;
	}

	/* Time interval when counters are tracked */
	rte_delay_ms(DLB2_IDLE_CNT_INTERVAL);

	/* Read the diff of counters after the interval */
	ret = read(fd[0], buf, sizeof(buf));
	if (ret < 0)
		return -errno;

	/* read_format structure updated after read() */
	for (i = 0; i < rf->num_counters; i++) {
		index = rf->values[i].counter_index;
		val = rf->values[i].counter_value;
		if (index == counter_id[DLB2_SCHED_CNT])
			data->ldb_perf_sched_cnt = val;
		else if (index == counter_id[DLB2_NO_WORK_CNT])
			data->ldb_perf_nowork_idle_cnt = val;
		else if (index == counter_id[DLB2_NO_SPACE_CNT])
			data->ldb_perf_nospace_idle_cnt = val;
		else if (index == counter_id[DLB2_PFRICTION_CNT])
			data->ldb_perf_pfriction_idle_cnt = val;
		else if (index == counter_id[DLB2_IFLIMIT_CNT])
			data->ldb_perf_iflimit_idle_cnt = val;
		else if (index == counter_id[DLB2_FIDLIMIT_CNT])
			data->ldb_perf_fidlimit_idle_cnt = val;
		else if (index == counter_id[DLB2_PROC_ON_CNT])
			data->perf_proc_on_cnt = val;
		else if (index == counter_id[DLB2_CLK_ON_CNT])
			data->perf_clk_on_cnt = val;
		else if (index == counter_id[DLB2_HCW_ERR_CNT])
			data->hcw_err_cnt = val;
	}

	ret = ioctl(fd[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
	if (ret != 0) {
		DLB2_LOG_ERR("dlb2: perf disable ioctl error\n");
		return -errno;
	}

	return 0;
}

static int
dlb2_perf_get_sched_idle_counts(struct dlb2_hw_dev *handle,
				void *idle_counts)
{
	struct dlb2_sched_idle_counts *data = idle_counts;
	int pmu_type;
	int ret = 0;

	/* DLB2 Perf PMU value that is initialized during perf init
	 * is read from sysfs filesystem.
	 */
	pmu_type = dlb2_get_pmu_type(handle->device_id);
	if (pmu_type <= 0) {
		DLB2_LOG_ERR("dlb2: perf pmu not supported\n");
		return -1;
	}

	/* Counters read with perf ioctls */
	ret = dlb2_read_perf_sched_idle_counts(pmu_type,
					       data);
	return ret;
}

/* Begin IOCTLS that take a device fd */

int
dlb2_ioctl_get_device_version(struct dlb2_hw_dev *handle,
			      uint8_t *revision,
			      uint8_t *version)
{
	struct dlb2_get_device_version_args ioctl_args = {0};

	int ret = ioctl(dlb2_device_fd[handle->device_id],
			DLB2_IOC_GET_DEVICE_VERSION,
			(unsigned long)&ioctl_args);
	if (!ret) {
		*revision = DLB2_DEVICE_REVISION(ioctl_args.response.id);
		*version = DLB2_DEVICE_VERSION(ioctl_args.response.id);
		*version -= 2; /* Mapping from kernel vals to PMD vals */
	}
	return (ret != 0) ? -errno : 0;
}

int
dlb2_ioctl_get_num_resources(struct dlb2_hw_dev *handle,
			     struct dlb2_get_num_resources_args *rsrcs)
{
	int ret = ioctl(dlb2_device_fd[handle->device_id],
			DLB2_IOC_GET_NUM_RESOURCES,
			(unsigned long)rsrcs);

	return (ret != 0) ? -errno : 0;
}

int
dlb2_ioctl_sched_domain_create(struct dlb2_hw_dev *handle,
			       struct dlb2_create_sched_domain_args *args)
{
	int ret = ioctl(dlb2_device_fd[handle->device_id],
			DLB2_IOC_CREATE_SCHED_DOMAIN, (unsigned long)args);

	if (ret == 0)
		dlb2_domain_fd[handle->device_id][args->response.id] =
			args->domain_fd;

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		struct rte_mp_reply mp_reply;
		int fd, ret;
		uint8_t id[2];

		id[0] = args->response.id;
		id[1] = handle->device_id;
		fd = args->domain_fd;

		ret = dlb2_send_mp_sync_request(DLB2_MP_DOMAIN_FD_PUBLISH,
						&id, sizeof(id), fd, &mp_reply);
		if (ret)
			return ret;

		free(mp_reply.msgs);
	}

	return (ret != 0) ? -errno : 0;
}

/* Begin IOCTLS that take a domain fd */
int
dlb2_ioctl_ldb_queue_create(struct dlb2_hw_dev *handle,
			    struct dlb2_create_ldb_queue_args *args)
{
	int ret = dlb2_domain_open(handle);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}

	ret = ioctl(dlb2_domain_fd[handle->device_id][handle->domain_id],
		    DLB2_IOC_CREATE_LDB_QUEUE,
		    (unsigned long)args);

	return (ret != 0) ? -errno : 0;
}

int
dlb2_ioctl_dir_queue_create(struct dlb2_hw_dev *handle,
			    struct dlb2_create_dir_queue_args *args)
{
	int ret = dlb2_domain_open(handle);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}

	ret = ioctl(dlb2_domain_fd[handle->device_id][handle->domain_id],
		    DLB2_IOC_CREATE_DIR_QUEUE,
		    (unsigned long)args);

	return (ret != 0) ? -errno : 0;
}

int
dlb2_ioctl_ldb_port_create(struct dlb2_hw_dev *handle,
			   struct dlb2_create_ldb_port_args *args,
			   enum dlb2_cq_poll_modes poll_mode __rte_unused,
			   uint8_t evdev_id)
{
	RTE_SET_USED(evdev_id);
	int ret = dlb2_domain_open(handle);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}

	ret = ioctl(dlb2_domain_fd[handle->device_id][handle->domain_id],
		    DLB2_IOC_CREATE_LDB_PORT, (unsigned long)args);

	return (ret != 0) ? -errno : 0;
}

int
dlb2_ioctl_dir_port_create(struct dlb2_hw_dev *handle,
			   struct dlb2_create_dir_port_args *args,
			   enum dlb2_cq_poll_modes poll_mode __rte_unused,
			   uint8_t evdev_id)
{
	RTE_SET_USED(evdev_id);
	int ret = dlb2_domain_open(handle);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}

	ret = ioctl(dlb2_domain_fd[handle->device_id][handle->domain_id],
		    DLB2_IOC_CREATE_DIR_PORT, (unsigned long)args);

	return (ret != 0) ? -errno : 0;
}

int
dlb2_ioctl_map_qid(struct dlb2_hw_dev *handle,
		   struct dlb2_map_qid_args *args)
{
	int ret = dlb2_domain_open(handle);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}

	ret = ioctl(dlb2_domain_fd[handle->device_id][handle->domain_id],
		    DLB2_IOC_MAP_QID, (unsigned long)args);

	return (ret != 0) ? -errno : 0;
}

int
dlb2_ioctl_unmap_qid(struct dlb2_hw_dev *handle,
		     struct dlb2_unmap_qid_args *args)
{
	int ret = dlb2_domain_open(handle);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}

	ret = ioctl(dlb2_domain_fd[handle->device_id][handle->domain_id],
		    DLB2_IOC_UNMAP_QID, (unsigned long)args);

	return (ret != 0) ? -errno : 0;
}

int
dlb2_ioctl_sched_domain_start(struct dlb2_hw_dev *handle,
			      struct dlb2_start_domain_args *args)
{
	int ret = dlb2_domain_open(handle);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}

	ret = ioctl(dlb2_domain_fd[handle->device_id][handle->domain_id],
		    DLB2_IOC_START_DOMAIN, (unsigned long)args);

	return (ret != 0) ? -errno : 0;
}

int dlb2_ioctl_sched_domain_stop(struct dlb2_hw_dev *handle,
				 struct dlb2_stop_domain_args *args) {
	int ret = dlb2_domain_open(handle);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}

	ret = ioctl(dlb2_domain_fd[handle->device_id][handle->domain_id],
		    DLB2_IOC_STOP_DOMAIN, (unsigned long)args);

	return (ret != 0) ? -errno : 0;
}

int
dlb2_ioctl_block_on_cq_interrupt(struct dlb2_hw_dev *handle,
				 int port_id,
				 bool is_ldb,
				 volatile void *cq_va,
				 uint8_t cq_gen,
				 bool arm)
{
	struct dlb2_block_on_cq_interrupt_args ioctl_args = {0};

	ioctl_args.port_id = port_id;
	ioctl_args.is_ldb = is_ldb;
	ioctl_args.cq_va = (uintptr_t)cq_va;
	ioctl_args.cq_gen = cq_gen;
	ioctl_args.arm = arm;

	int ret = dlb2_domain_open(handle);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}

	ret = ioctl(dlb2_domain_fd[handle->device_id][handle->domain_id],
		    DLB2_IOC_BLOCK_ON_CQ_INTERRUPT,
		    (unsigned long)&ioctl_args);

	return (ret != 0) ? -errno : 0;
}

int
dlb2_ioctl_get_ldb_queue_depth(struct dlb2_hw_dev *handle,
			       struct dlb2_get_ldb_queue_depth_args *args)
{
	int ret = dlb2_domain_open(handle);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}

	ret = ioctl(dlb2_domain_fd[handle->device_id][handle->domain_id],
		    DLB2_IOC_GET_LDB_QUEUE_DEPTH, (unsigned long)args);

	return (ret != 0) ? -errno : 0;
}

int
dlb2_ioctl_pending_port_unmaps(struct dlb2_hw_dev *handle,
			       struct dlb2_pending_port_unmaps_args *args)
{
	int ret = dlb2_domain_open(handle);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}

	ret = ioctl(dlb2_domain_fd[handle->device_id][handle->domain_id],
		    DLB2_IOC_PENDING_PORT_UNMAPS, (unsigned long)args);

	return (ret != 0) ? -errno : 0;
}

int
dlb2_ioctl_get_dir_queue_depth(struct dlb2_hw_dev *handle,
			       struct dlb2_get_dir_queue_depth_args *args)
{
	int ret = dlb2_domain_open(handle);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}

	ret = ioctl(dlb2_domain_fd[handle->device_id][handle->domain_id],
		    DLB2_IOC_GET_DIR_QUEUE_DEPTH, (unsigned long)args);

	return (ret != 0) ? -errno : 0;
}

static int
dlb2_ioctl_get_sn_allocation(struct dlb2_hw_dev *handle,
			     struct dlb2_get_sn_allocation_args *args)
{
	int ret = ioctl(dlb2_device_fd[handle->device_id],
			DLB2_IOC_GET_SN_ALLOCATION, (unsigned long)args);

	return (ret != 0) ? -errno : 0;
}

static int
dlb2_ioctl_set_sn_allocation(struct dlb2_hw_dev *handle,
			     struct dlb2_set_sn_allocation_args *args)
{
	int ret = ioctl(dlb2_device_fd[handle->device_id],
			DLB2_IOC_SET_SN_ALLOCATION, (unsigned long)args);

	return (ret != 0) ? -errno : 0;
}

static int
dlb2_ioctl_get_sn_occupancy(struct dlb2_hw_dev *handle,
			    struct dlb2_get_sn_occupancy_args *args)
{
	int ret = ioctl(dlb2_device_fd[handle->device_id],
			DLB2_IOC_GET_SN_OCCUPANCY, (unsigned long)args);

	return (ret != 0) ? -errno : 0;
}

static int dlb2_ioctl_get_port_fd(int fd, int port_id, uint32_t ioc)
{
	struct dlb2_get_port_fd_args ioctl_args = {0};
	int ret;

	ioctl_args.port_id = port_id;

	ret = ioctl(fd, ioc, (unsigned long)&ioctl_args);

	return (ret != 0) ? -errno : (int)ioctl_args.response.id;
}

static int dlb2_ioctl_port_ctrl(struct dlb2_port *qm_port, bool enable)
{
	int domain_fd, ret;

	domain_fd = dlb2_domain_fd[qm_port->dlb2->qm_instance.device_id]
				  [qm_port->dlb2->qm_instance.domain_id];

	if (PORT_TYPE(qm_port) == DLB2_LDB_PORT) {
		if (enable) {
			struct dlb2_enable_ldb_port_args args = {.port_id = qm_port->id};

			ret = ioctl(domain_fd, DLB2_IOC_ENABLE_LDB_PORT, (unsigned long)&args);
		} else {
			struct dlb2_disable_ldb_port_args args = {.port_id = qm_port->id};

			ret = ioctl(domain_fd, DLB2_IOC_DISABLE_LDB_PORT, (unsigned long)&args);
		}
	} else {
		if (enable) {
			struct dlb2_enable_dir_port_args args = {.port_id = qm_port->id};

			ret = ioctl(domain_fd, DLB2_IOC_ENABLE_DIR_PORT, (unsigned long)&args);
		} else {
			struct dlb2_disable_dir_port_args args = {.port_id = qm_port->id};

			ret = ioctl(domain_fd, DLB2_IOC_DISABLE_DIR_PORT, (unsigned long)&args);
		}
	}

	return (ret != 0) ? -errno : 0;
}

static int dlb2_ioctl_get_ldb_port_pp_fd(int fd, int port_id)
{
	return dlb2_ioctl_get_port_fd(fd, port_id, DLB2_IOC_GET_LDB_PORT_PP_FD);
}

static int dlb2_ioctl_get_ldb_port_cq_fd(int fd, int port_id)
{
	return dlb2_ioctl_get_port_fd(fd, port_id, DLB2_IOC_GET_LDB_PORT_CQ_FD);
}

static int dlb2_ioctl_get_dir_port_pp_fd(int fd, int port_id)
{
	return dlb2_ioctl_get_port_fd(fd, port_id, DLB2_IOC_GET_DIR_PORT_PP_FD);
}

static int dlb2_ioctl_get_dir_port_cq_fd(int fd, int port_id)
{
	return dlb2_ioctl_get_port_fd(fd, port_id, DLB2_IOC_GET_DIR_PORT_CQ_FD);
}

static int
dlb2_eventdev_name_to_dev_names(const char *name, char *dev_path,
				int dev_path_id, char *dev_name, int *id)
{
	int len, ret;

	/* Expected name is of the form qm_dlb2X or qm_dlb2XX */
	len = strnlen(name, DLB2_MAX_DEVICE_PATH);

	if (len == 10) {
		*id = 0;
	} else if (len >= 11 && len <= 12) {
		ret = dlb2_string_to_int(id, &name[10]);
		if (ret < 0)
			return ret;

		if (*id >= DLB2_MAX_NUM_DOMAINS) {
			DLB2_LOG_ERR("Bad eventdev id %d >= %d\n",
				     *id, DLB2_MAX_NUM_DOMAINS);
			return -EINVAL;
		}
	} else {
		DLB2_LOG_ERR("Bad eventdev name %s - unsafe\n",
			     name);
		return -EINVAL;
	}

	snprintf(dev_path,
		 DLB2_MAX_DEVICE_PATH,
		 "/dev/dlb%d",
		 dev_path_id);

	snprintf(dev_name,
		 DLB2_MAX_DEVICE_PATH,
		 "dlb2%d",
		 *id);

	return 0;
}

static int
dlb2_hw_open(struct dlb2_hw_dev *handle, const char *name)
{
	if (name == NULL)
		return -EINVAL;

	if (dlb2_eventdev_name_to_dev_names(name,
					    &handle->device_path[0],
					    handle->device_path_id,
				 &handle->device_name[0],
				 &handle->device_id)) {
		DLB2_LOG_ERR("dlb2: could not derive device path for %s\n",
			     name);
		return -EINVAL;
	}

	/* Do nothing if already open */
	if (dlb2_device_fd[handle->device_id] < 0) {
		DLB2_LOG_DBG("Open DLB2 device %s\n", handle->device_path);

		dlb2_device_fd[handle->device_id] = open(handle->device_path,
							 O_RDWR);

		if (dlb2_device_fd[handle->device_id] < 0) {
			DLB2_LOG_ERR("open failed: device_path %s\n",
				     handle->device_path);
			perror("open(): ");
			return -EINVAL;
		}
	}
#ifdef DLB2_DEBUG
	else
		DLB2_LOG_DBG("%s already open\n", handle->device_path);
#endif

	return 0;
}

static int
dlb2_hwdev_open(struct dlb2_hw_dev *handle,
		const char *name)
{
	int socket_id = rte_socket_id();

	if (name == NULL)
		return -EINVAL;

	RTE_LOG(INFO, PMD, "Initialising DLB2 %s on NUMA node %d\n", name,
		socket_id);

	/* First verify that we can open the driver */
	if (dlb2_hw_open(handle, name) != 0) {
		DLB2_LOG_ERR("could not open driver %s\n", name);
		return -EINVAL;
	}

	handle->info.socket_id = socket_id;

	return 0;
}

static int
dlb2_ioctl_enable_cq_weight(struct dlb2_hw_dev *handle,
		     struct dlb2_enable_cq_weight_args *args)
{
	int ret = dlb2_domain_open(handle);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}

	ret = ioctl(dlb2_domain_fd[handle->device_id][handle->domain_id],
		    DLB2_IOC_ENABLE_CQ_WEIGHT, (unsigned long)args);

	return (ret != 0) ? -errno : 0;
}

static int
dlb2_ioctl_set_cq_inflight_ctrl(struct dlb2_hw_dev *handle,
		     struct dlb2_cq_inflight_ctrl_args *args)
{
	int ret = dlb2_domain_open(handle);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: open domain device file failed\n");
		return ret;
	}

	ret = ioctl(dlb2_domain_fd[handle->device_id][handle->domain_id],
		    DLB2_IOC_SET_CQ_INFLIGHT_CTRL, (unsigned long)args);

	return (ret != 0) ? -errno : 0;
}

static void
dlb2_iface_fn_ptrs_init(void)
{
	dlb2_iface_low_level_io_init = dlb2_low_level_io_init;
	dlb2_iface_open = dlb2_hwdev_open;
	dlb2_iface_domain_reset = dlb2_device_reset;
	dlb2_iface_get_device_version = dlb2_ioctl_get_device_version;
	dlb2_iface_get_num_resources = dlb2_ioctl_get_num_resources;
	dlb2_iface_sched_domain_create = dlb2_ioctl_sched_domain_create;
	dlb2_iface_ldb_queue_create = dlb2_ioctl_ldb_queue_create;
	dlb2_iface_dir_queue_create = dlb2_ioctl_dir_queue_create;
	dlb2_iface_ldb_port_create = dlb2_ioctl_ldb_port_create;
	dlb2_iface_dir_port_create = dlb2_ioctl_dir_port_create;
	dlb2_iface_map_qid = dlb2_ioctl_map_qid;
	dlb2_iface_unmap_qid = dlb2_ioctl_unmap_qid;
	dlb2_iface_sched_domain_start = dlb2_ioctl_sched_domain_start;
	dlb2_iface_sched_domain_stop = dlb2_ioctl_sched_domain_stop;
	dlb2_iface_block_on_cq_interrupt = dlb2_ioctl_block_on_cq_interrupt;
	dlb2_iface_pending_port_unmaps = dlb2_ioctl_pending_port_unmaps;
	dlb2_iface_get_ldb_queue_depth = dlb2_ioctl_get_ldb_queue_depth;
	dlb2_iface_get_dir_queue_depth = dlb2_ioctl_get_dir_queue_depth;
	dlb2_iface_get_sn_allocation = dlb2_ioctl_get_sn_allocation;
	dlb2_iface_set_sn_allocation = dlb2_ioctl_set_sn_allocation;
	dlb2_iface_get_sn_occupancy = dlb2_ioctl_get_sn_occupancy;
	dlb2_iface_get_cq_poll_mode = dlb2_ioctl_get_cq_poll_mode;
	dlb2_iface_hardware_init = dlb2_ioctl_hardware_init;
	dlb2_iface_port_mmap = dlb2_mmap_all;
	dlb2_iface_get_sched_idle_counts = dlb2_perf_get_sched_idle_counts;
	dlb2_iface_enable_cq_weight = dlb2_ioctl_enable_cq_weight;
	dlb2_iface_set_cq_inflight_ctrl = dlb2_ioctl_set_cq_inflight_ctrl;
	dlb2_iface_port_ctrl = dlb2_ioctl_port_ctrl;
}

static int
check_pci_addr(const char *buf, int bufsize)
{
	union splitaddr {
		struct {
			char *domain;
			char *bus;
			char *devid;
			char *function;
		};
		char *str[PCI_FMT_NVAL];
	} splitaddr;

	char *buf_copy = strndup(buf, bufsize);
	if (buf_copy == NULL)
		return -1;

	if (rte_strsplit(buf_copy, bufsize, splitaddr.str, PCI_FMT_NVAL, ':')
			!= PCI_FMT_NVAL - 1)
		goto error;

	splitaddr.function = strchr(splitaddr.devid, '.');
	if (splitaddr.function == NULL)
		goto error;

	free(buf_copy);
	return 0;
error:
	free(buf_copy);
	return -1;
}

static int
dlb2_get_dev_version(void)
{
	DIR *dir;
	char dirname[PATH_MAX];
	char filename[PATH_MAX];
	unsigned long devId, vendorId;
	struct dirent *e;

	dir = opendir(rte_pci_get_sysfs_path());
	if (dir == NULL) {
		RTE_LOG(ERR, EAL, "%s(): opendir failed: %s\n",
			__func__, strerror(errno));
		return -1;
	}

	while ((e = readdir(dir)) != NULL) {
		if (check_pci_addr(e->d_name, sizeof(e->d_name)))
			continue;

		snprintf(dirname, sizeof(dirname), "%s/%s",
			 rte_pci_get_sysfs_path(), e->d_name);

		snprintf(filename, sizeof(filename), "%s/vendor", dirname);
		if (eal_parse_sysfs_value(filename, &vendorId) < 0)
			return -1;

		snprintf(filename, sizeof(filename), "%s/device", dirname);
		if (eal_parse_sysfs_value(filename, &devId) < 0)
			return -1;

		if (((devId == PCI_DEVICE_ID_INTEL_DLB2_5_PF)  ||
		     (devId == PCI_DEVICE_ID_INTEL_DLB2_5_VF)) &&
		    (vendorId == PCI_VENDOR_ID_INTEL))
			return DLB2_HW_V2_5;
		else if (((devId == PCI_DEVICE_ID_INTEL_DLB2_PF)  ||
			  (devId == PCI_DEVICE_ID_INTEL_DLB2_VF)) &&
		    (vendorId == PCI_VENDOR_ID_INTEL))
			return DLB2_HW_V2;
	}

	closedir(dir);

	return -1;
}

static int
event_dlb2_vdev_probe(struct rte_vdev_device *vdev)
{
	struct rte_eventdev *dev;
	const char *name;
	int ret;
	int q;
	struct dlb2_devargs dlb2_args = {
		.socket_id = rte_socket_id(),
		.max_num_events = DLB2_MAX_NUM_LDB_CREDITS,
		.num_dir_credits_override = -1,
		.hwdev_id = 0,
		.qid_depth_thresholds = { {0} },
		.producer_coremask = {'\0'},
		.sw_credit_quanta = {DLB2_SW_CREDIT_QUANTA_DEFAULT,
			DLB2_SW_CREDIT_P_QUANTA_DEFAULT,
			DLB2_SW_CREDIT_C_QUANTA_DEFAULT},
		.hw_credit_quanta = {DLB2_SW_CREDIT_BATCH_SZ,
			DLB2_SW_CREDIT_P_BATCH_SZ,
			DLB2_SW_CREDIT_C_BATCH_SZ},
		.max_cq_depth = DLB2_DEFAULT_CQ_DEPTH,
		.max_enq_depth = DLB2_MAX_ENQUEUE_DEPTH,
		.use_default_hl = true,
		.alloc_hl_entries = 0
	};

	for (q = 0; q < DLB2_MAX_NUM_PORTS_ALL; q++)
		dlb2_args.port_cos.cos_id[q] = DLB2_COS_DEFAULT;

	/* runtime init of globals */
	dlb2_low_level_io_init();

	name = rte_vdev_device_name(vdev);

	if (name == NULL) {
		DLB2_LOG_ERR("rte_vdev_device_name failed for secondary");
		return -EFAULT;
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		const char *params;
		int version = dlb2_get_dev_version();

		if (version == -1) {
			DLB2_LOG_ERR("failed to get vdev device version\n");
			return -EINVAL;
		}

		if (version == DLB2_HW_V2_5)
			dlb2_args.max_num_events =
				DLB2_MAX_NUM_CREDITS(version);

		params = rte_vdev_device_args(vdev);

		DLB2_LOG_DBG("%s : %s\n", name, params);

		ret = dlb2_parse_params(params, name, &dlb2_args, version);
		if (ret) {
			DLB2_LOG_ERR("failed to parse vdev args");
			return -EINVAL;
		}
	}

	dev = rte_event_pmd_vdev_init(name,
				      sizeof(struct dlb2_eventdev),
				      dlb2_args.socket_id);
	if (dev == NULL) {
		DLB2_LOG_ERR("eventdev vdev init() failed");
		return -EFAULT;
	}

	dlb2_iface_fn_ptrs_init();

	rte_spinlock_init(&dlb2_domain_fd_lock);

	if (rte_eal_process_type() == RTE_PROC_PRIMARY)
		ret = dlb2_primary_eventdev_probe(dev,
						  name,
						  &dlb2_args,
						  DLB2_IS_VDEV);
	else
		ret = dlb2_secondary_eventdev_probe(dev,
						    name,
						    DLB2_IS_VDEV);
	if (ret)
		return ret;

	event_dev_probing_finish(dev);

	return 0;
}

static int
event_dlb2_vdev_remove(struct rte_vdev_device *vdev)
{
	const char *name;
	int ret;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	RTE_LOG(INFO, PMD, "Closing eventdev dlb2 device %s\n", name);

	ret = dlb2_uninit(name);

	return ret;
}

static struct rte_vdev_driver vdev_eventdev_dlb2_pmd = {
	.probe = event_dlb2_vdev_probe,
	.remove = event_dlb2_vdev_remove,
};

RTE_PMD_REGISTER_VDEV(EVDEV_DLB2_NAME_PMD, vdev_eventdev_dlb2_pmd);
RTE_PMD_REGISTER_PARAM_STRING(EVDEV_DLB2_NAME_PMD,
	NUMA_NODE_ARG "=<int> "
	DLB2_MAX_NUM_EVENTS "=<int> "
	DLB2_NUM_DIR_CREDITS "=<int> "
	DLB2_NUM_ORDERED_QUEUES_0 "=<int> "
	DLB2_NUM_ORDERED_QUEUES_1 "=<int> "
	HWDEV_ID_ARG "=<int> "
);
