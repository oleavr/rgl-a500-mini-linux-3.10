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

#ifndef __SUNXI_I2S_H__
#define __SUNXI_I2S_H__
#include "sunxi_dma.h"
struct sunxi_i2s {
	struct clk *pllclk;
	struct clk *moduleclk;
	void __iomem  *sunxi_i2s_membase;
	struct sunxi_dma_params play_dma_param;
	struct sunxi_dma_params capture_dma_param;
	struct snd_soc_dai_driver dai;
};
#endif