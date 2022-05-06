/*
 * Copyright (C) 2016
 * Allwinner Technology Co., Ltd. <www.allwinnertech.com>
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef _SUNXI_LINUX_CLK_PERPARE_H
#define _SUNXI_LINUX_CLK_PERPARE_H

#ifdef CONFIG_SUNXI_CLK_PREPARE
extern int sunxi_clk_enable_prepare(struct clk *clk);
extern int sunxi_clk_disable_prepare(struct clk *clk);
#else
static int sunxi_clk_enable_prepare(struct clk *clk){return 0;};
static int sunxi_clk_disable_prepare(struct clk *clk){ return 0; };
#endif /* CONFIG_SUNXI_CLK_PREPARE */
#endif /* _SUNXI_LINUX_CLK_PERPARE_H */
