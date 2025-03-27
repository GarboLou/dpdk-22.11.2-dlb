/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2020 Intel Corporation
 */

#ifndef _DLB2_INLINE_FNS_H_
#define _DLB2_INLINE_FNS_H_

#include <eventdev_pmd.h>

/* Inline functions required in more than one source file. */

static inline struct dlb2_eventdev *
dlb2_pmd_priv(const struct rte_eventdev *eventdev)
{
	return eventdev->data->dev_private;
}

static inline void
dlb2_movntdq(void *pp_addr, void *qe4)
{
	/* Move entire 64B cache line of QEs, 128 bits (16B) at a time. */
	long long *_qe  = (long long *)qe4;

	__v2di src_data0 = (__v2di){_qe[0], _qe[1]};
	__v2di src_data1 = (__v2di){_qe[2], _qe[3]};
	__v2di src_data2 = (__v2di){_qe[4], _qe[5]};
	__v2di src_data3 = (__v2di){_qe[6], _qe[7]};

	__builtin_ia32_movntdq((__v2di *)pp_addr + 0, (__v2di)src_data0);
	rte_wmb();
	__builtin_ia32_movntdq((__v2di *)pp_addr + 1, (__v2di)src_data1);
	rte_wmb();
	__builtin_ia32_movntdq((__v2di *)pp_addr + 2, (__v2di)src_data2);
	rte_wmb();
	__builtin_ia32_movntdq((__v2di *)pp_addr + 3, (__v2di)src_data3);
	rte_wmb();
}

static inline void
dlb2_movntdq_single(void *pp_addr, void *qe4)
{
	long long *_qe  = (long long *)qe4;
	__m128i src_data0 = (__m128i){_qe[0], _qe[1]};

	_mm_stream_si128(pp_addr, src_data0);
}

static inline void
dlb2_movdir64b_single(void *pp_addr, void *qe4)
{
	asm volatile(".byte 0x66, 0x0f, 0x38, 0xf8, 0x02"
		:
	: "a" (pp_addr), "d" (qe4));
}


static inline void
dlb2_movdir64b(void *dest, void *src)
{
	asm volatile(".byte 0x66, 0x0f, 0x38, 0xf8, 0x02"
		:
	: "a" (dest), "d" (src));
}

#endif /* _DLB2_INLINE_FNS_H_ */
