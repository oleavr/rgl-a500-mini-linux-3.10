/*
 * linux-3.10/drivers/video/sunxi/disp2/disp/de/eink_buffer_manager.h
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


#ifndef __EINK_BUFFER_MANAGER_H__
#define __EINK_BUFFER_MANAGER_H__

#include "disp_eink.h"

s32 ring_buffer_manager_init();
s32 ring_buffer_manager_exit();
bool is_ring_queue_full();
bool is_ring_queue_empty();
u8* get_current_image();
u8* get_last_image();
s32 queue_image(u32 mode,  struct area_info update_area);
s32 dequeue_image();

#endif
