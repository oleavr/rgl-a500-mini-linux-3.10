/*
 *      Filename: google_vp9.h
 *      Version: 0.01alpha
 *      Description: Video engine driver API, Don't modify it in user space.
 *      License: GPLv2
 *      Author  : yangcaoyuan<yangcaoyuan@allwinnertech.com>
 *      Date    : 2017/04/04
 *
 *      Copyright (C) 2015 Allwinnertech Ltd.
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License version 2 as
 *      published by the Free Software Foundation.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */


#ifndef _GOOGLE_VP9_H_
#define _GOOGLE_VP9_H_

enum IOCTL_CMD {
	VP9_IOCTL_UNKOWN = 0x100,
	VP9_IOCTL_GET_ENV_INFO,
	VP9_IOCTL_WAIT_INTERRUPT,
	VP9_IOCTL_RESET,
	VP9_IOCTL_SET_FREQ,
	VP9_IOCTL_SET_HIGH_PERF_MSG,

	VP9_IOCTL_ENGINE_REQ,
	VP9_IOCTL_ENGINE_REL,

	/*for iommu*/
	IOCTL_GET_IOMMU_ADDR,
	IOCTL_FREE_IOMMU_ADDR,
};

struct vp9_env_infomation {
	unsigned int phymem_start;
	int  phymem_total_size;
	unsigned long  address_macc;
};

struct __vp9_task {
	int task_prio;
	int ID;
	unsigned long timeout;
	unsigned int frametime;
	unsigned int block_mode;
};

struct vp9_engine_task {
	struct __vp9_task t;
	struct list_head list;
	struct task_struct *task_handle;
	unsigned int status;
	unsigned int running;
	unsigned int is_first_task;
};

struct vp9_regop {
	unsigned long addr;
	unsigned int value;
};

struct vp9_env_infomation_compat {
	unsigned int phymem_start;
	int  phymem_total_size;
	u32  address_macc;
};

struct vp9_regop_compat {
	u32 addr;
	unsigned int value;
};

/*--------------------------------------------------------------*/


#endif
