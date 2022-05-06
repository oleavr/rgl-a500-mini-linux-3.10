/*
 * Copyright (c) 2007-2017 Allwinnertech Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef __SUNXI_RW_FUNC__
#define __SUNXI_RW_FUNC__
#include <linux/io.h>
#include <linux/module.h>
extern u32 read_prcm_wvalue(u32 addr,void __iomem * ADDA_PR_CFG_REG);

extern void write_prcm_wvalue(u32 addr, u32 val,void __iomem * ADDA_PR_CFG_REG);

extern u32 codec_wrreg_prcm_bits(void __iomem * ADDA_PR_CFG_REG,u32 reg, u32 mask, u32 value);

extern u32 codec_wrreg_bits(void __iomem * address, u32	mask,	u32 value);


extern u32 codec_wr_control(void __iomem * reg, u32 mask, u32 shift, u32 val);
extern void codec_wrreg(void __iomem * address,u32 val);
extern u32 codec_rdreg(void __iomem * address);

extern u32 audiodebug_reg_read(u32 reg);

#endif
