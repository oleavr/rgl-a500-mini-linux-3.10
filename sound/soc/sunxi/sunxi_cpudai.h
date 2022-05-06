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

#ifndef __SUNXI_CPUDAI_H__
#define __SUNXI_CPUDAI_H__

#if defined(CONFIG_ARCH_SUN3IW1)
#include "sun3iw1_codec.h"
#elif defined(CONFIG_ARCH_SUN8IW10)
#include "sun8iw10_codec.h"
#elif defined(CONFIG_ARCH_SUN8IW11)
#include "sun8iw11_codec.h"
#elif defined(CONFIG_ARCH_SUN50IW2)
#include "sun50iw2_codec.h"
#endif

#endif	/* __SUNXI_CPUDAI_H__ */
