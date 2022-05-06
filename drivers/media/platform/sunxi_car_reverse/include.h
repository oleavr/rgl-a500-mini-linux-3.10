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


#ifndef __CAR_REVERSE_MISC_H__
#define __CAR_REVERSE_MISC_H__

#include "car_reverse.h"

struct buffer_pool *
		alloc_buffer_pool(struct device *dev, int depth, int buf_size);
void free_buffer_pool(struct device *dev, struct buffer_pool *bp);
void rest_buffer_pool(struct device *dev, struct buffer_pool *bp);
void dump_buffer_pool(struct device *dev, struct buffer_pool *bp);

int preview_output_start(struct preview_params *params);
int preview_output_stop(void);
void preview_update(struct buffer_node *frame);

int video_source_connect(struct preview_params *params);
int video_source_disconnect(struct preview_params *params);
int video_source_streamon(void);
int video_source_streamoff(void);

struct buffer_node *video_source_dequeue_buffer(void);
void video_source_queue_buffer(struct buffer_node *node);

#endif
