/*
 * linux-3.10/drivers/video/sunxi/disp2/disp/de/disp_hdmi.h
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

#ifndef __DISP_HDMI_H__
#define __DISP_HDMI_H__

#include "disp_private.h"

s32 disp_init_hdmi(disp_bsp_init_para * para);

struct disp_device* disp_get_hdmi(u32 disp);

#endif
