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

/*
*********************************************************************************************************
*                                                    LINUX-KERNEL
*                                        AllWinner Linux Platform Develop Kits
*                                                   Kernel Module
*
*                                    (c) Copyright 2006-2011, kevin.z China
*                                             All Rights Reserved
*
* File    : mem_twi.h
* By      : kevin.z
* Version : v1.0
* Date    : 2011-5-31 15:15
* Descript:
* Update  : date                auther      ver     notes
*********************************************************************************************************
*/

#ifndef __MEM_TWI_H__
#define __MEM_TWI_H__

typedef struct tag_twic_reg {
	volatile unsigned int reg_saddr;
	volatile unsigned int reg_xsaddr;
	volatile unsigned int reg_data;
	volatile unsigned int reg_ctl;
	volatile unsigned int reg_status;
	volatile unsigned int reg_clkr;
	volatile unsigned int reg_reset;
	volatile unsigned int reg_efr;
	volatile unsigned int reg_lctl;

} __twic_reg_t;

extern __s32 mem_twi_save(int group);
extern __s32 mem_twi_restore(void);

#endif	/*__MEM_TWI_H__*/
