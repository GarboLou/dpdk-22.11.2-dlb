
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019-2020 Intel Corporation

if not is_linux or not dpdk_conf.has('RTE_ARCH_X86_64')
        build = false
        reason = 'only supported on x86_64 Linux'
        subdir_done()
endif

sources = files('dlb2.c',
		'dlb2_iface.c',
		'dlb2_xstats.c',
		'pf/dlb2_main.c',
		'pf/dlb2_pf.c',
		'pf/base/dlb2_resource.c',
		'rte_pmd_dlb2.c',
		'dlb2_selftest.c'
)

if host_machine.system() == 'linux'
	sources += files('bifurcated/dlb2_vdev.c')
endif

headers = files('dlb2_frag.h', 'rte_pmd_dlb2.h')

deps += ['mbuf', 'mempool', 'ring', 'pci', 'bus_pci', 'bus_vdev']

if meson.version().version_compare('> 0.58.0')
fs = import('fs')
dlb_options = fs.read('meson_options.txt').strip().split('\n')

foreach opt: dlb_options
	if (opt.strip().startswith('#') or opt.strip() == '')
		continue
	endif
	cflags += '-D' + opt.strip().to_upper().replace(' ','')
endforeach
endif
