/*
 * linux-3.10/drivers/video/sunxi/disp2/disp/de/disp_manager.h
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

#ifndef __DISP_MANAGER_H__
#define __DISP_MANAGER_H__

#include "disp_private.h"

s32 disp_init_mgr(disp_bsp_init_para * para);
s32 __disp_config_transfer2inner(struct disp_layer_config_inner *cfg_inner,
				      struct disp_layer_config *config);
s32 __disp_config2_transfer2inner(struct disp_layer_config_inner *cfg_inner,
				      struct disp_layer_config2 *config2);

#if defined(CONFIG_SUNXI_IOMMU)
#define DE_MASTOR_ID 0
extern void sunxi_enable_device_iommu(unsigned int mastor_id, bool flag);
#endif

#endif
