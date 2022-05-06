/*
 * linux-3.10/drivers/video/sunxi/disp2/disp/de/lowlevel_sun8iw11/de_vep.h
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

//*********************************************************************************************************************
//  All Winner Tech, All Right Reserved. 2014-2015 Copyright (c)
//
//  File name   :	de_vep.h
//
//  Description :	display engine 2.0 vep basic function declaration
//
//  History     :	2014/04/24  iptang  v0.1  Initial version
//
//*********************************************************************************************************************

#ifndef __DE_VEP_H__
#define __DE_VEP_H__

int de_fcc_init(unsigned int sel, unsigned int reg_base);
int de_fcc_update_regs(unsigned int sel);
int de_fcc_set_reg_base(unsigned int sel, unsigned int chno, void *base);
int de_fcc_csc_set(unsigned int sel, unsigned int chno, unsigned int en, unsigned int mode);

#endif
