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

#ifndef __STANDBY_DRAM_
#define __STANDBY_DRAM_

s32 standby_dram_crc_enable(pm_dram_para_t *pdram_state);
u32 standby_dram_crc(pm_dram_para_t *pdram_state);

#endif				/* __STANDBY_DRAM_ */
