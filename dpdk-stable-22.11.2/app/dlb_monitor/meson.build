# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019-2021 Intel Corporation

allow_experimental_apis = true

if not dpdk_conf.has('RTE_EVENT_DLB2')
	message('DLB PMD not present; skipping dlb_monitor build')
	build = false
	subdir_done()
endif

sources = files('main.c')
deps += ['eventdev', 'event_dlb2']
