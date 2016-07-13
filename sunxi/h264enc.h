/*
 * Copyright (c) 2014-2015 Jens Kuske <jenskuske@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 */

#ifndef __H264ENC_H__
#define __H264ENC_H__

struct h264enc_params {
	unsigned int width;
	unsigned int height;

	unsigned int src_width;
	unsigned int src_height;
	enum color_format { H264_FMT_NV12 = 0, H264_FMT_NV16 = 1 } src_format;

	unsigned int profile_idc, level_idc;

	enum { H264_EC_CAVLC = 0, H264_EC_CABAC = 1 } entropy_coding_mode;

	unsigned int qp;

	unsigned int keyframe_interval;
};

typedef struct h264enc_internal h264enc;

h264enc *h264enc_new(const struct h264enc_params *p);
void h264enc_free(h264enc *c);
void *h264enc_get_input_buffer(const h264enc *c);
void *h264enc_get_bytestream_buffer(const h264enc *c);
unsigned int h264enc_get_bytestream_length(const h264enc *c);
int h264enc_encode_picture(h264enc *c);

#endif
