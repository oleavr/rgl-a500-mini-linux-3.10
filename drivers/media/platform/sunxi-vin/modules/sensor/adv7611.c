/*
 * A V4L2 driver for adv7611 ic.
 *
 * Copyright (c) 2017 by Allwinnertech Co., Ltd.  http://www.allwinnertech.com
 *
 * Authors:  zhengjiangwei<zhengjiangwei@allwinnertech.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/delay.h>
#include <linux/videodev2.h>
#include <linux/clk.h>
#include <media/v4l2-device.h>
#include <media/v4l2-chip-ident.h>
#include <media/v4l2-mediabus.h>
#include <linux/io.h>

#include "camera.h"
#include "sensor_helper.h"

MODULE_AUTHOR("zjw");
MODULE_DESCRIPTION("A low-level driver for adv7611 ic");
MODULE_LICENSE("GPL");

#define MCLK			  (24*1000*1000)
int MCLK_DIV = 1;

#define VREF_POL			V4L2_MBUS_VSYNC_ACTIVE_HIGH
#define HREF_POL			V4L2_MBUS_HSYNC_ACTIVE_HIGH
#define CLK_POL				V4L2_MBUS_PCLK_SAMPLE_RISING
#define V4L2_IDENT_SENSOR 0x7611

#define SENSOR_NAME "adv7611"

/*
 * Our nominal (default) frame rate.
 */
#define SENSOR_FRAME_RATE 30
/*
 * The adv7611 sits on i2c with ID 0x98
 */
#define I2C_ADDR 0x98

unsigned char gIo_saddr = 0x98>>1;
unsigned char gCec_saddr = 0x80>>1;
unsigned char gInfo_saddr = 0x7C>>1;
unsigned char gDpll_saddr = 0x4C>>1;
unsigned char gKsv_saddr = 0x64>>1;
unsigned char gEdid_saddr = 0x6C>>1;
unsigned char gHdmi_saddr = 0x68>>1;
unsigned char gCp_saddr = 0x44>>1;

typedef enum {
	ADV7611_NO_SIGNAL_CONNECTED = 0,
	RES_480P60,
	RES_720P60,
	RES_1080P24,
	RES_1080P30,
	RES_1080P60,
	ADV7611_UNSUPPORTED_RESOLUTION_CONNECTED
} ADV7611_RES;

static inline int general_write(struct v4l2_subdev *sd, u8 reg, u8 val)
{
	cci_set_saddr(sd, gIo_saddr);
	return sensor_write(sd, reg, val);
}

static inline int io_read(struct v4l2_subdev *sd, u8 reg)
{
	unsigned short value = 0;
	cci_set_saddr(sd, gIo_saddr);
	sensor_read(sd, reg, &value);
	return value;
}

static inline int io_write(struct v4l2_subdev *sd, u8 reg, u8 val)
{
	cci_set_saddr(sd, gIo_saddr);
	return sensor_write(sd, reg, val);
}

static inline int io_write_and_or(struct v4l2_subdev *sd, u8 reg, u8 mask, u8 val)
{
	return io_write(sd, reg, (io_read(sd, reg) & mask) | val);
}

static inline int cec_read(struct v4l2_subdev *sd, u8 reg)
{
	unsigned short value = 0;
	cci_set_saddr(sd, gCec_saddr);
	sensor_read(sd, reg, &value);
	return value;
}

static inline int cec_write(struct v4l2_subdev *sd, u8 reg, u8 val)
{
	cci_set_saddr(sd, gCec_saddr);
	return sensor_write(sd, reg, val);
}

static inline int cec_write_and_or(struct v4l2_subdev *sd, u8 reg, u8 mask, u8 val)
{
	return cec_write(sd, reg, (cec_read(sd, reg) & mask) | val);
}

static inline int infoframe_read(struct v4l2_subdev *sd, u8 reg)
{
	unsigned short value = 0;
	cci_set_saddr(sd, gInfo_saddr);
	sensor_read(sd, reg, &value);
	return value;
}

static inline int infoframe_write(struct v4l2_subdev *sd, u8 reg, u8 val)
{
	cci_set_saddr(sd, gInfo_saddr);
	return sensor_write(sd, reg, val);
}

static inline int dpll_read(struct v4l2_subdev *sd, u8 reg)
{
	unsigned short value = 0;
	cci_set_saddr(sd, gDpll_saddr);
	sensor_read(sd, reg, &value);
	return value;
}

static inline int dpll_write(struct v4l2_subdev *sd, u8 reg, u8 val)
{
	cci_set_saddr(sd, gDpll_saddr);
	return sensor_write(sd, reg, val);
}

static inline int ksv_read(struct v4l2_subdev *sd, u8 reg)
{
	unsigned short value = 0;
	cci_set_saddr(sd, gKsv_saddr);
	sensor_read(sd, reg, &value);
	return value;
}

static inline int ksv_write(struct v4l2_subdev *sd, u8 reg, u8 val)
{
	cci_set_saddr(sd, gKsv_saddr);
	return sensor_write(sd, reg, val);
}

static inline int edid_read(struct v4l2_subdev *sd, u8 reg)
{
	unsigned short value = 0;
	cci_set_saddr(sd, gEdid_saddr);
	sensor_read(sd, reg, &value);
	return value;
}

static inline int edid_write(struct v4l2_subdev *sd, u8 reg, u8 val)
{
	cci_set_saddr(sd, gEdid_saddr);
	return sensor_write(sd, reg, val);
}

static inline int hdmi_read(struct v4l2_subdev *sd, u8 reg)
{
	unsigned short value = 0;
	cci_set_saddr(sd, gHdmi_saddr);
	sensor_read(sd, reg, &value);
	return value;
}

static inline int hdmi_write(struct v4l2_subdev *sd, u8 reg, u8 val)
{
	cci_set_saddr(sd, gHdmi_saddr);
	return sensor_write(sd, reg, val);
}
static inline int cp_read(struct v4l2_subdev *sd, u8 reg)
{
	unsigned short value = 0;
	cci_set_saddr(sd, gCp_saddr);
	sensor_read(sd, reg, &value);
	return value;
}

static inline int cp_write(struct v4l2_subdev *sd, u8 reg, u8 val)
{
	cci_set_saddr(sd, gCp_saddr);
	return sensor_write(sd, reg, val);
}


/* ----------------------------------------------------------------------- */
void hdmi_edid_set(struct v4l2_subdev *sd)
{
	io_write(sd, 0x40, 0xe3);
	io_write(sd, 0x41, 0xe7);
	ksv_write(sd, 0x74, 0x00);
	ksv_write(sd, 0x77, 0x00);
	edid_write(sd, 0x00, 0x00);
	edid_write(sd, 0x01, 0xFF);
	edid_write(sd, 0x02, 0xFF);
	edid_write(sd, 0x03, 0xFF);
	edid_write(sd, 0x04, 0xFF);
	edid_write(sd, 0x05, 0xFF);
	edid_write(sd, 0x06, 0xFF);
	edid_write(sd, 0x07, 0x00);
	edid_write(sd, 0x08, 0x41);
	edid_write(sd, 0x09, 0x99);
	edid_write(sd, 0x0a, 0x00);
	edid_write(sd, 0x0b, 0x00);
	edid_write(sd, 0x0c, 0x00);
	edid_write(sd, 0x0d, 0x00);
	edid_write(sd, 0x0e, 0x00);
	edid_write(sd, 0x0f, 0x00);
	edid_write(sd, 0x10, 0x00);
	edid_write(sd, 0x11, 0x00);
	edid_write(sd, 0x12, 0x01);
	edid_write(sd, 0x13, 0x03);
	edid_write(sd, 0x14, 0x80);
	edid_write(sd, 0x15, 0x00);
	edid_write(sd, 0x16, 0x00);
	edid_write(sd, 0x17, 0x78);
	edid_write(sd, 0x18, 0x0E);
	edid_write(sd, 0x19, 0xEE);
	edid_write(sd, 0x1a, 0x91);
	edid_write(sd, 0x1b, 0xA3);
	edid_write(sd, 0x1c, 0x54);
	edid_write(sd, 0x1d, 0x4C);
	edid_write(sd, 0x1e, 0x99);
	edid_write(sd, 0x1f, 0x26);
	edid_write(sd, 0x20, 0x0F);
	edid_write(sd, 0x21, 0x50);
	edid_write(sd, 0x22, 0x54);
	edid_write(sd, 0x23, 0x21);
	edid_write(sd, 0x24, 0x08);
	edid_write(sd, 0x25, 0x00);
	edid_write(sd, 0x26, 0x81);
	edid_write(sd, 0x27, 0x80);
	edid_write(sd, 0x28, 0xB3);
	edid_write(sd, 0x29, 0x00);
	edid_write(sd, 0x2a, 0xA9);
	edid_write(sd, 0x2b, 0x40);
	edid_write(sd, 0x2c, 0x01);
	edid_write(sd, 0x2d, 0x01);
	edid_write(sd, 0x2e, 0x01);
	edid_write(sd, 0x2f, 0x01);
	edid_write(sd, 0x30, 0x01);
	edid_write(sd, 0x31, 0x01);
	edid_write(sd, 0x32, 0x01);
	edid_write(sd, 0x33, 0x01);
	edid_write(sd, 0x34, 0x01);
	edid_write(sd, 0x35, 0x01);
	edid_write(sd, 0x36, 0x02);
	edid_write(sd, 0x37, 0x3A);
	edid_write(sd, 0x38, 0x80);
	edid_write(sd, 0x39, 0x18);
	edid_write(sd, 0x3a, 0x71);
	edid_write(sd, 0x3b, 0x38);
	edid_write(sd, 0x3c, 0x2D);
	edid_write(sd, 0x3d, 0x40);
	edid_write(sd, 0x3e, 0x58);
	edid_write(sd, 0x3f, 0x2C);
	edid_write(sd, 0x40, 0x45);
	edid_write(sd, 0x41, 0x00);
	edid_write(sd, 0x42, 0x00);
	edid_write(sd, 0x43, 0x00);
	edid_write(sd, 0x44, 0x00);
	edid_write(sd, 0x45, 0x00);
	edid_write(sd, 0x46, 0x00);
	edid_write(sd, 0x47, 0x1E);
	edid_write(sd, 0x48, 0x01);
	edid_write(sd, 0x49, 0x1D);
	edid_write(sd, 0x4a, 0x00);
	edid_write(sd, 0x4b, 0x72);
	edid_write(sd, 0x4c, 0x51);
	edid_write(sd, 0x4d, 0xD0);
	edid_write(sd, 0x4e, 0x1E);
	edid_write(sd, 0x4f, 0x20);
	edid_write(sd, 0x50, 0x6E);
	edid_write(sd, 0x51, 0x28);
	edid_write(sd, 0x52, 0x55);
	edid_write(sd, 0x53, 0x00);
	edid_write(sd, 0x54, 0x00);
	edid_write(sd, 0x55, 0x00);
	edid_write(sd, 0x56, 0x00);
	edid_write(sd, 0x57, 0x00);
	edid_write(sd, 0x58, 0x00);
	edid_write(sd, 0x59, 0x1E);
	edid_write(sd, 0x5A, 0x02);
	edid_write(sd, 0x5B, 0x3A);
	edid_write(sd, 0x5C, 0x80);
	edid_write(sd, 0x5D, 0xD0);
	edid_write(sd, 0x5E, 0x72);
	edid_write(sd, 0x5F, 0x38);
	edid_write(sd, 0x60, 0x2D);
	edid_write(sd, 0x61, 0x40);
	edid_write(sd, 0x62, 0x10);
	edid_write(sd, 0x63, 0x2C);
	edid_write(sd, 0x64, 0x45);
	edid_write(sd, 0x65, 0x80);
	edid_write(sd, 0x66, 0x00);
	edid_write(sd, 0x67, 0x00);
	edid_write(sd, 0x68, 0x00);
	edid_write(sd, 0x69, 0x00);
	edid_write(sd, 0x6a, 0x00);
	edid_write(sd, 0x6b, 0x1E);
	edid_write(sd, 0x6c, 0x01);
	edid_write(sd, 0x6d, 0x1D);
	edid_write(sd, 0x6e, 0x00);
	edid_write(sd, 0x6f, 0xBC);
	edid_write(sd, 0x70, 0x52);
	edid_write(sd, 0x71, 0xD0);
	edid_write(sd, 0x72, 0x1E);
	edid_write(sd, 0x73, 0x20);
	edid_write(sd, 0x74, 0xB8);
	edid_write(sd, 0x75, 0x28);
	edid_write(sd, 0x76, 0x55);
	edid_write(sd, 0x77, 0x40);
	edid_write(sd, 0x78, 0x00);
	edid_write(sd, 0x79, 0x00);
	edid_write(sd, 0x7a, 0x00);
	edid_write(sd, 0x7b, 0x00);
	edid_write(sd, 0x7c, 0x00);
	edid_write(sd, 0x7d, 0x1E);
	edid_write(sd, 0x7e, 0x01);
	edid_write(sd, 0x7f, 0xC5);
	edid_write(sd, 0x80, 0x02);
	edid_write(sd, 0x81, 0x03);
	edid_write(sd, 0x82, 0x19);
	edid_write(sd, 0x83, 0x70);
	edid_write(sd, 0x84, 0x46);
	edid_write(sd, 0x85, 0x10);
	edid_write(sd, 0x86, 0x04);
	edid_write(sd, 0x87, 0x1F);
	edid_write(sd, 0x88, 0x13);
	edid_write(sd, 0x89, 0x05);
	edid_write(sd, 0x8a, 0x14);
	edid_write(sd, 0x8b, 0x23);
	edid_write(sd, 0x8c, 0x09);
	edid_write(sd, 0x8d, 0x07);
	edid_write(sd, 0x8e, 0x01);
	edid_write(sd, 0x8f, 0x83);
	edid_write(sd, 0x90, 0x01);
	edid_write(sd, 0x91, 0x00);
	edid_write(sd, 0x92, 0x00);
	edid_write(sd, 0x93, 0x65);
	edid_write(sd, 0x94, 0x03);
	edid_write(sd, 0x95, 0x0C);
	edid_write(sd, 0x96, 0x00);
	edid_write(sd, 0x97, 0x10);
	edid_write(sd, 0x98, 0x00);
	edid_write(sd, 0x99, 0x30);
	edid_write(sd, 0x9a, 0x2A);
	edid_write(sd, 0x9b, 0x00);
	edid_write(sd, 0x9c, 0x98);
	edid_write(sd, 0x9d, 0x51);
	edid_write(sd, 0x9e, 0x00);
	edid_write(sd, 0x9f, 0x2A);
	edid_write(sd, 0xa0, 0x40);
	edid_write(sd, 0xa1, 0x30);
	edid_write(sd, 0xa2, 0x70);
	edid_write(sd, 0xa3, 0x13);
	edid_write(sd, 0xa4, 0x00);
	edid_write(sd, 0xa5, 0x00);
	edid_write(sd, 0xa6, 0x00);
	edid_write(sd, 0xa7, 0x00);
	edid_write(sd, 0xa8, 0x00);
	edid_write(sd, 0xa9, 0x00);
	edid_write(sd, 0xaa, 0x1E);
	edid_write(sd, 0xab, 0x0E);
	edid_write(sd, 0xac, 0x1F);
	edid_write(sd, 0xad, 0x00);
	edid_write(sd, 0xae, 0x80);
	edid_write(sd, 0xaf, 0x51);
	edid_write(sd, 0xb0, 0x00);
	edid_write(sd, 0xb1, 0x1E);
	edid_write(sd, 0xb2, 0x30);
	edid_write(sd, 0xb3, 0x40);
	edid_write(sd, 0xb4, 0x80);
	edid_write(sd, 0xb5, 0x37);
	edid_write(sd, 0xb6, 0x00);
	edid_write(sd, 0xb7, 0x00);
	edid_write(sd, 0xb8, 0x00);
	edid_write(sd, 0xb9, 0x00);
	edid_write(sd, 0xba, 0x00);
	edid_write(sd, 0xbb, 0x00);
	edid_write(sd, 0xbc, 0x1C);
	edid_write(sd, 0xbd, 0x21);
	edid_write(sd, 0xbe, 0x39);
	edid_write(sd, 0xbf, 0x90);
	edid_write(sd, 0xc0, 0x30);
	edid_write(sd, 0xc1, 0x62);
	edid_write(sd, 0xc2, 0x1A);
	edid_write(sd, 0xc3, 0x27);
	edid_write(sd, 0xc4, 0x40);
	edid_write(sd, 0xc5, 0x68);
	edid_write(sd, 0xc6, 0xB0);
	edid_write(sd, 0xc7, 0x36);
	edid_write(sd, 0xc8, 0x00);
	edid_write(sd, 0xc9, 0x00);
	edid_write(sd, 0xca, 0x00);
	edid_write(sd, 0xcb, 0x00);
	edid_write(sd, 0xcc, 0x00);
	edid_write(sd, 0xcd, 0x00);
	edid_write(sd, 0xce, 0x1C);
	edid_write(sd, 0xcf, 0x48);
	edid_write(sd, 0xd0, 0x3F);
	edid_write(sd, 0xd1, 0x40);
	edid_write(sd, 0xd2, 0x30);
	edid_write(sd, 0xd3, 0x62);
	edid_write(sd, 0xd4, 0xB0);
	edid_write(sd, 0xd5, 0x32);
	edid_write(sd, 0xd6, 0x40);
	edid_write(sd, 0xd7, 0x40);
	edid_write(sd, 0xd8, 0xC0);
	edid_write(sd, 0xd9, 0x13);
	edid_write(sd, 0xda, 0x00);
	edid_write(sd, 0xdb, 0x00);
	edid_write(sd, 0xdc, 0x00);
	edid_write(sd, 0xdd, 0x00);
	edid_write(sd, 0xde, 0x00);
	edid_write(sd, 0xdf, 0x00);
	edid_write(sd, 0xe0, 0x1E);
	edid_write(sd, 0xe1, 0x00);
	edid_write(sd, 0xe2, 0x00);
	edid_write(sd, 0xe3, 0x00);
	edid_write(sd, 0xe4, 0x00);
	edid_write(sd, 0xe5, 0x00);
	edid_write(sd, 0xe6, 0x00);
	edid_write(sd, 0xe7, 0x00);
	edid_write(sd, 0xe8, 0x00);
	edid_write(sd, 0xe9, 0x00);
	edid_write(sd, 0xea, 0x00);
	edid_write(sd, 0xeb, 0x00);
	edid_write(sd, 0xec, 0x00);
	edid_write(sd, 0xed, 0x00);
	edid_write(sd, 0xef, 0x00);
	edid_write(sd, 0xf0, 0x00);
	edid_write(sd, 0xf1, 0x00);
	edid_write(sd, 0xf2, 0x00);
	edid_write(sd, 0xf3, 0x00);
	edid_write(sd, 0xf4, 0x00);
	edid_write(sd, 0xf5, 0x00);
	edid_write(sd, 0xf6, 0x00);
	edid_write(sd, 0xf7, 0x00);
	edid_write(sd, 0xf8, 0x00);
	edid_write(sd, 0xf9, 0x00);
	edid_write(sd, 0xfa, 0x00);
	edid_write(sd, 0xfb, 0x00);
	edid_write(sd, 0xfc, 0x00);
	edid_write(sd, 0xfd, 0x00);
	edid_write(sd, 0xfe, 0xF0);
	edid_write(sd, 0xff, 0xB1);
	ksv_write(sd, 0x77, 0x00);
	ksv_write(sd, 0x52, 0x20);
	ksv_write(sd, 0x53, 0x00);
	ksv_write(sd, 0x70, 0x9E);
	ksv_write(sd, 0x74, 0x03);
	io_write(sd, 0x40, 0xe2);
	io_write(sd, 0x41, 0xe6);
}
void set_port_resolution(struct v4l2_subdev *sd, ADV7611_RES res)
{
	switch (res) {
	case RES_1080P30:
	case RES_1080P24:
	case RES_720P60:
	case RES_480P60:
		sensor_dbg("When we set 1080P30 1080P24 720P60 480P60,they should use the same register setting!\n");
		io_write(sd, 0x01, 0x46);/*Prim_Mode = 110b HDMI-GR zjw*/
		io_write(sd, 0x02, 0xF5);
		io_write(sd, 0x03, 0x00);/*8-bit SDR ITU-656 mode zjw*/
		/*io_write(sd, 0x04, 0x62);*/
		io_write(sd, 0x05, 0x2c);/*AV Codes Off, add time code in data
								stream and Blanking data*/
		io_write(sd, 0x06, 0xa0);/*Invert VS,HS pins*/
		io_write(sd, 0x0b, 0x44);/*Power up part*/
		io_write(sd, 0x0c, 0x42);/*Power up part*/
		io_write(sd, 0x14, 0x7f);/*Max Drive Strength*/
		io_write(sd, 0x15, 0x80);/*Disable Tristate of Pins*/
		io_write(sd, 0x19, 0xC1);/*use 8-bit SDR ITU-656 mode ,so should
								set this .*/
		io_write(sd, 0x33, 0x40);/*use 8-bit SDR ITU-656 mode ,so should
								set this .*/
		io_write(sd, 0x41, 0x30);/*set audio I2S bclk*/
		cp_write(sd, 0xba, 0x01);/*Set HDMI FreeRun*/
		ksv_write(sd, 0x40, 0x81);/*Disable HDCP 1.1 features*/
		hdmi_write(sd, 0x9b, 0x03);
		hdmi_write(sd, 0xc1, 0x01);
		hdmi_write(sd, 0xc2, 0x01);
		hdmi_write(sd, 0xc3, 0x01);
		hdmi_write(sd, 0xc4, 0x01);
		hdmi_write(sd, 0xc5, 0x01);
		hdmi_write(sd, 0xc6, 0x01);
		hdmi_write(sd, 0xc7, 0x01);
		hdmi_write(sd, 0xc8, 0x01);
		hdmi_write(sd, 0xc9, 0x01);
		hdmi_write(sd, 0xca, 0x01);
		hdmi_write(sd, 0xcb, 0x01);
		hdmi_write(sd, 0xcc, 0x01);
		hdmi_write(sd, 0x00, 0x00);
		hdmi_write(sd, 0x83, 0xFE);
		hdmi_write(sd, 0x6F, 0x0C);
		hdmi_write(sd, 0x85, 0x1F);
		hdmi_write(sd, 0x87, 0x70);
		hdmi_write(sd, 0x8D, 0x04);
		hdmi_write(sd, 0x8E, 0x1E);
		hdmi_write(sd, 0x1A, 0x8A);
		hdmi_write(sd, 0x57, 0xDA);
		hdmi_write(sd, 0x58, 0x01);
		hdmi_write(sd, 0x03, 0x98);
		hdmi_write(sd, 0x75, 0x10);
		break;
	case RES_1080P60:
		sensor_dbg("We do not support 1080p 60 fps in 8 bits BT656!\n");
		break;
	default:
		break;
	}
}
static int adv7611_core_init(struct v4l2_subdev *sd)
{
	/*reset the device*/
	sensor_dbg("reset the device !\n");
	io_write(sd, 0xFF, 0x80);
	msleep(10);
	io_write(sd, 0xFF, 0x00);

	/*Set slave addr*/
	sensor_dbg("set the address map!\n");
	io_write(sd, 0xF4, gCec_saddr<<1);
	io_write(sd, 0xF5, gInfo_saddr<<1);
	io_write(sd, 0xF8, gDpll_saddr<<1);
	io_write(sd, 0xF9, gKsv_saddr<<1);
	io_write(sd, 0xFA, gEdid_saddr<<1);
	io_write(sd, 0xFB, gHdmi_saddr<<1);
	io_write(sd, 0xFD, gCp_saddr<<1);

	sensor_dbg("hdmi_edid_set\n");
	hdmi_edid_set(sd);

	/*set port resolution*/
	sensor_dbg("set_port_resolution \n");
	set_port_resolution(sd, RES_1080P30);

	msleep(10);
	sensor_dbg("io reg(0x%x[0]) = 0x%x, test the input status from cable!\n",
		0x6F, io_read(sd, 0x6F));
	sensor_dbg("io reg(0x%x[4]) = 0x%x, check the hdmi in clock !\n",
		0x6A, io_read(sd, 0x6A));
	sensor_dbg("hdmi reg(0x%x[1]) = 0x%x, check the hdmi pll clock !\n",
		0x04, hdmi_read(sd, 0x04));
	sensor_dbg("we find the hdmi clock not be locked ,so we read the register TMDSFREQ[0] and TMDSFREQ_FRAC[6:0] reg(0x52[7])=0x%x  \n",
		hdmi_read(sd, 0x52));
	sensor_dbg("we find the hdmi clock not be locked ,so we read the register TMDSFREQ[8:1] reg(0x51[7:0])=0x%x \n",
		hdmi_read(sd, 0x51));
	sensor_dbg("hdmi reg(0x%x[6]) = 0x%x, check the hdmi content encryption !\n",
		0x05, hdmi_read(sd, 0x05));
	sensor_dbg("hdmi reg(0x%x[5]) = 0x%x, check the De generation lock !\n",
		0x07, hdmi_read(sd, 0x07));

	return 0;
}


/*
 * Stuff that knows about the sensor.
 */
static int sensor_power(struct v4l2_subdev *sd, int on)
{
	int ret;
	ret = 0;
	switch (on) {
	case STBY_ON:
		sensor_dbg("STBY_ON!\n");
		cci_lock(sd);
		vin_set_mclk(sd, OFF);
		cci_unlock(sd);
		break;
	case STBY_OFF:
		/*we are not support STBY mode in adv7611 now!*/
		sensor_dbg("STBY_OFF!\n");
		cci_lock(sd);
		vin_set_mclk_freq(sd, MCLK);
		vin_set_mclk(sd, ON);
		usleep_range(10000, 12000);
		cci_unlock(sd);
		break;
	case PWR_ON:
		sensor_dbg("PWR_ON!\n");
		cci_lock(sd);
		vin_gpio_set_status(sd, RESET, CSI_GPIO_HIGH);/*set the gpio to output*/
		vin_gpio_write(sd, RESET, CSI_GPIO_HIGH);
		vin_set_mclk_freq(sd, MCLK);
		vin_set_mclk(sd, ON);
		usleep_range(10000, 12000);
		/*reset*/
		vin_gpio_write(sd, RESET, CSI_GPIO_LOW);
		usleep_range(10000, 12000);
		vin_gpio_write(sd, RESET, CSI_GPIO_HIGH);
		usleep_range(10000, 12000);
		cci_unlock(sd);
		break;
	case PWR_OFF:
		sensor_dbg("PWR_OFF!\n");
		cci_lock(sd);
		vin_set_mclk(sd, OFF);
		cci_unlock(sd);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int sensor_reset(struct v4l2_subdev *sd, u32 val)
{
	switch (val) {
	case 0:
		vin_gpio_write(sd, RESET, CSI_GPIO_HIGH);
		usleep_range(10000, 12000);
		break;
	case 1:
		vin_gpio_write(sd, RESET, CSI_GPIO_LOW);
		usleep_range(10000, 12000);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int sensor_detect(struct v4l2_subdev *sd)
{
	sensor_dbg("sensor_detect\n");
	if (1) {
		sensor_dbg("io reg(0xEA) = 0x%x\n",  io_read(sd, 0xEA));
		msleep(10);
		if (0x20 == io_read(sd, 0xEA)) {
			sensor_dbg("We get the id !!!\n");
		} else{
			sensor_dbg("We do not get the id !!!\n");
		}
	}
	return 0;
}
static int sensor_init(struct v4l2_subdev *sd, u32 val)
{
	struct sensor_info *info = to_state(sd);

	sensor_dbg("sensor_init\n");
	sensor_detect(sd);

	adv7611_core_init(sd);

	info->focus_status = 0;
	info->low_speed = 0;
	info->width = HD1080_WIDTH;
	info->height = HD1080_HEIGHT;
	info->hflip = 0;
	info->vflip = 0;
	info->gain = 0;

	info->tpf.numerator = 1;
	info->tpf.denominator = 30;	/* 30fps */
	info->preview_first_flag = 1;
	return 0;
}


static long sensor_ioctl(struct v4l2_subdev *sd, unsigned int cmd, void *arg)
{
	return -EINVAL;
}

/*
 * Store information about the video data format.
 */
static struct regval_list sensor_fmt_raw[] = {
};

static struct sensor_format_struct sensor_formats[] = {
	{
		.desc = "YUYV 4:2:2",
		.mbus_code = V4L2_MBUS_FMT_UYVY8_2X8,
		.regs = sensor_fmt_raw,
		.regs_size = ARRAY_SIZE(sensor_fmt_raw),
		.bpp = 1,
	},
};

#define N_FMTS ARRAY_SIZE(sensor_formats)

/*
 * Then there is the issue of window sizes.  Try to capture the info here.
 */

static struct sensor_win_size sensor_win_sizes[] = {
	/* 1080P */
	{
	 .width = HD1080_WIDTH,
	 .height = HD1080_HEIGHT,
	 .hoffset = 0,
	 .voffset = 0,
	 .regs = sensor_fmt_raw,
	 .regs_size = ARRAY_SIZE(sensor_fmt_raw),
	 .set_size = NULL,
	 },
	/* 720p */
	{
	 .width = HD720_WIDTH,
	 .height = HD720_HEIGHT,
	 .hoffset = 0,
	 .voffset = 0,
	 .hts = 1750,
	 .vts = 800,
	 .pclk = 42 * 1000 * 1000,
	 .fps_fixed = 1,
	 .bin_factor = 1,
	 .intg_min = 1,
	 .intg_max = 800 << 4,
	 .gain_min = 1 << 4,
	 .gain_max = 10 << 4,
	 .regs = sensor_fmt_raw,
	 .regs_size = ARRAY_SIZE(sensor_fmt_raw),
	 .set_size = NULL,
	 },
	/* VGA */
	{
	 .width = VGA_WIDTH,
	 .height = VGA_HEIGHT,
	 .hoffset = 0,
	 .voffset = 0,
	 .hts = 640,
	 .vts = 480,
	 .pclk = 9216 * 1000,
	 .fps_fixed = 1,
	 .bin_factor = 1,
	 .intg_min = 1,
	 .intg_max = 480 << 4,
	 .gain_min = 1 << 4,
	 .gain_max = 10 << 4,
	 .regs = sensor_fmt_raw,
	 .regs_size = ARRAY_SIZE(sensor_fmt_raw),
	 .set_size = NULL,
	 },
};
#define N_WIN_SIZES (ARRAY_SIZE(sensor_win_sizes))
static int sensor_g_mbus_config(struct v4l2_subdev *sd,
				struct v4l2_mbus_config *cfg)
{
	cfg->type = V4L2_MBUS_BT656;
	cfg->flags = CLK_POL | CSI_CH_0;
	return 0;
}

/*
 * Code for dealing with controls.
 * fill with different sensor module
 * different sensor module has different settings here
 * if not support the follow function ,retrun -EINVAL
 */

/* *****************************begin of ******************************* */
static int sensor_queryctrl(struct v4l2_subdev *sd, struct v4l2_queryctrl *qc)
{
	/* Fill in min, max, step and default value for these controls. */
	/* see include/linux/videodev2.h for details */
	return -EINVAL;
}

static int sensor_g_ctrl(struct v4l2_subdev *sd, struct v4l2_control *ctrl)
{
	sensor_dbg("sensor_g_ctrl\n");
	return -EINVAL;
}

static int sensor_s_ctrl(struct v4l2_subdev *sd, struct v4l2_control *ctrl)
{
	sensor_dbg("sensor_s_ctrl\n");
	return -EINVAL;
}

static int sensor_g_chip_ident(struct v4l2_subdev *sd,
				   struct v4l2_dbg_chip_ident *chip)
{
	struct i2c_client *client = v4l2_get_subdevdata(sd);
	return v4l2_chip_ident_i2c_client(client, chip, V4L2_IDENT_SENSOR, 0);
}

static int sensor_reg_init(struct sensor_info *info)
{
	sensor_dbg("sensor_reg_init\n");
	return  0;
}

static int sensor_s_stream(struct v4l2_subdev *sd, int enable)
{
	struct sensor_info *info = to_state(sd);
	sensor_print("%s on = %d, %d*%d %x\n", __func__, enable,
		  info->current_wins->width,
		  info->current_wins->height, info->fmt->mbus_code);

	if (!enable)
		return 0;
	return sensor_reg_init(info);
}

/* ----------------------------------------------------------------------- */

static const struct v4l2_subdev_core_ops sensor_core_ops = {
	.g_chip_ident = sensor_g_chip_ident,
	.g_ctrl = sensor_g_ctrl,
	.s_ctrl = sensor_s_ctrl,
	.queryctrl = sensor_queryctrl,
	.reset = sensor_reset,
	.init = sensor_init,
	.s_power = sensor_power,
	.ioctl = sensor_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl32 = sensor_compat_ioctl32,
#endif
};

static const struct v4l2_subdev_video_ops sensor_video_ops = {
	.s_parm = sensor_s_parm,
	.g_parm = sensor_g_parm,
	.s_stream = sensor_s_stream,
	.g_mbus_config = sensor_g_mbus_config,
};

static const struct v4l2_subdev_pad_ops sensor_pad_ops = {
	.enum_mbus_code = sensor_enum_mbus_code,
	.enum_frame_size = sensor_enum_frame_size,
	.get_fmt = sensor_get_fmt,
	.set_fmt = sensor_set_fmt,
};

static const struct v4l2_subdev_ops sensor_ops = {
	.core = &sensor_core_ops,
	.video = &sensor_video_ops,
	.pad = &sensor_pad_ops,
};


/* ----------------------------------------------------------------------- */
static struct cci_driver cci_drv = {
	.name = SENSOR_NAME,
	.addr_width = CCI_BITS_8,
	.data_width = CCI_BITS_8,
};

static int sensor_probe(struct i2c_client *client,
			const struct i2c_device_id *id)
{
	struct v4l2_subdev *sd;
	struct sensor_info *info;

	info = kzalloc(sizeof(struct sensor_info), GFP_KERNEL);
	if (info == NULL)
		return -ENOMEM;
	sd = &info->sd;
	cci_dev_probe_helper(sd, client, &sensor_ops, &cci_drv);

	mutex_init(&info->lock);

	info->fmt = &sensor_formats[0];
	info->fmt_pt = &sensor_formats[0];
	info->win_pt = &sensor_win_sizes[0];
	info->fmt_num = N_FMTS;
	info->win_size_num = N_WIN_SIZES;
	info->sensor_field = V4L2_FIELD_NONE;
	info->af_first_flag = 1;
	info->auto_focus = 0;
	return 0;
}

static int sensor_remove(struct i2c_client *client)
{
	struct v4l2_subdev *sd;

	sd = cci_dev_remove_helper(client, &cci_drv);
	printk("sensor_remove adv7611 sd = %p!\n", sd);
	kfree(to_state(sd));
	return 0;
}

static const struct i2c_device_id sensor_id[] = {
	{SENSOR_NAME, 0},
	{}
};

MODULE_DEVICE_TABLE(i2c, sensor_id);
static struct i2c_driver sensor_driver = {
	.driver = {
		   .owner = THIS_MODULE,
		   .name = SENSOR_NAME,
		   },
	.probe = sensor_probe,
	.remove = sensor_remove,
	.id_table = sensor_id,
};
static __init int init_sensor(void)
{
	MCLK_DIV = 1;
	return cci_dev_init_helper(&sensor_driver);
}

static __exit void exit_sensor(void)
{
	cci_dev_exit_helper(&sensor_driver);
}

module_init(init_sensor);
module_exit(exit_sensor);
