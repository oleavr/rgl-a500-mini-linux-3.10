/*
 * linux-3.10/drivers/media/platform/sunxi-vin/vin-mipi/bsp_mipi_csi_null.c
 *
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

/*
 * sunxi mipi bsp interface
 * Author:wangxuan
 */
#include "bsp_mipi_csi.h"
#include "../utility/vin_io.h"

void bsp_mipi_csi_set_version(unsigned int sel, unsigned int ver)
{
	return;
}

int bsp_mipi_csi_set_base_addr(unsigned int sel, unsigned long addr_base)
{
	return 0;
}

int bsp_mipi_dphy_set_base_addr(unsigned int sel, unsigned long addr_base)
{
	return 0;
}

void bsp_mipi_csi_dphy_init(unsigned int sel)
{
	return;
}

void bsp_mipi_csi_dphy_exit(unsigned int sel)
{
	return;
}

void bsp_mipi_csi_dphy_enable(unsigned int sel)
{
	return;
}

void bsp_mipi_csi_dphy_disable(unsigned int sel)
{
	return;
}

void bsp_mipi_csi_protocol_enable(unsigned int sel)
{
	return;
}

void bsp_mipi_csi_protocol_disable(unsigned int sel)
{
	return;
}

void bsp_mipi_csi_set_para(unsigned int sel, struct mipi_para *para)
{
	return;
}

void bsp_mipi_csi_set_fmt(unsigned int sel, unsigned int total_rx_ch,
			  struct mipi_fmt_cfg *fmt)
{
	return;
}
