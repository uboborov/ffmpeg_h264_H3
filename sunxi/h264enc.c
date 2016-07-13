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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "h264enc.h"
#include "ve.h"

#define MSG(x) fprintf(stderr, "h264enc: " x "\n")

#define ALIGN(x, a) (((x) + ((typeof(x))(a) - 1)) & ~((typeof(x))(a) - 1))
#define IS_ALIGNED(x, a) (((x) & ((typeof(x))(a) - 1)) == 0)
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

struct h264enc_internal {
	unsigned int mb_width, mb_height, mb_stride;
	unsigned int crop_right, crop_bottom;

	struct ve_mem *luma_buffer;
	struct ve_mem *chroma_buffer;
	unsigned int input_buffer_size;
	enum color_format input_color_format;

	struct ve_mem *bytestream_buffer;
	unsigned int bytestream_buffer_size;
	unsigned int bytestream_length;

	struct h264enc_ref_pic {
		struct ve_mem *luma_buffer;
		struct ve_mem *chroma_buffer;
		struct ve_mem *extra_buffer; /* unknown purpose, looks like smaller luma */
	} ref_picture[2];

	struct ve_mem *extra_buffer_line, *extra_buffer_frame; /* unknown purpose */

	void *regs;

	unsigned int write_sps_pps;

	unsigned int profile_idc, level_idc, constraints;

	unsigned int entropy_coding_mode_flag;
	unsigned int pic_init_qp;

	unsigned int keyframe_interval;

	unsigned int current_frame_num;
	enum slice_type { SLICE_P = 0, SLICE_I = 2 } current_slice_type;

};

static void put_bits(void* regs, uint32_t x, int num)
{
	writel(x, regs + VE_AVC_BASIC_BITS);
	writel(0x1 | ((num & 0x1f) << 8), regs + VE_AVC_TRIGGER);
	/* again the problem, how to check for finish? */
}

static void put_ue(void* regs, uint32_t x)
{
	x++;
	put_bits(regs, x, (32 - __builtin_clz(x)) * 2 - 1);
}

static void put_se(void* regs, int x)
{
	x = 2 * x - 1;
	x ^= (x >> 31);
	put_ue(regs, x);
}

static void put_start_code(void* regs, unsigned int nal_ref_idc, unsigned int nal_unit_type)
{
	uint32_t tmp = readl(regs + VE_AVC_PARAM);

	/* disable emulation_prevention_three_byte */
	writel(tmp | (0x1 << 31), regs + VE_AVC_PARAM);

	put_bits(regs, 0, 24);
	put_bits(regs, 0x100 | (nal_ref_idc << 5) | (nal_unit_type << 0), 16);

	writel(tmp, regs + VE_AVC_PARAM);
}

static void put_rbsp_trailing_bits(void* regs)
{
	unsigned int cur_bs_len = readl(regs + VE_AVC_VLE_LENGTH);

	int num_zero_bits = 8 - ((cur_bs_len + 1) & 0x7);
	put_bits(regs, 1 << num_zero_bits, num_zero_bits + 1);
}

static void put_seq_parameter_set(h264enc *c)
{
	put_start_code(c->regs, 3, 7);

	put_bits(c->regs, c->profile_idc, 8);
	put_bits(c->regs, c->constraints, 8);
	put_bits(c->regs, c->level_idc, 8);

	put_ue(c->regs, /* seq_parameter_set_id = */ 0);

	put_ue(c->regs, /* log2_max_frame_num_minus4 = */ 0);
	put_ue(c->regs, /* pic_order_cnt_type = */ 2);

	put_ue(c->regs, /* max_num_ref_frames = */ 1);
	put_bits(c->regs, /* gaps_in_frame_num_value_allowed_flag = */ 0, 1);

	put_ue(c->regs, c->mb_width - 1);
	put_ue(c->regs, c->mb_height - 1);

	put_bits(c->regs, /* frame_mbs_only_flag = */ 1, 1);

	put_bits(c->regs, /* direct_8x8_inference_flag = */ 0, 1);

	unsigned int frame_cropping_flag = c->crop_right || c->crop_bottom;
	put_bits(c->regs, frame_cropping_flag, 1);
	if (frame_cropping_flag)
	{
		put_ue(c->regs, 0);
		put_ue(c->regs, c->crop_right);
		put_ue(c->regs, 0);
		put_ue(c->regs, c->crop_bottom);
	}

	put_bits(c->regs, /* vui_parameters_present_flag = */ 0, 1);

	put_rbsp_trailing_bits(c->regs);
}

static void put_pic_parameter_set(h264enc *c)
{
	put_start_code(c->regs, 3, 8);

	put_ue(c->regs, /* pic_parameter_set_id = */ 0);
	put_ue(c->regs, /* seq_parameter_set_id = */ 0);

	put_bits(c->regs, c->entropy_coding_mode_flag, 1);

	put_bits(c->regs, /* bottom_field_pic_order_in_frame_present_flag = */ 0, 1);
	put_ue(c->regs, /* num_slice_groups_minus1 = */ 0);

	put_ue(c->regs, /* num_ref_idx_l0_default_active_minus1 = */ 0);
	put_ue(c->regs, /* num_ref_idx_l1_default_active_minus1 = */ 0);

	put_bits(c->regs, /* weighted_pred_flag = */ 0, 1);
	put_bits(c->regs, /* weighted_bipred_idc = */ 0, 2);

	put_se(c->regs, (int)c->pic_init_qp - 26);
	put_se(c->regs, (int)c->pic_init_qp - 26);
	put_se(c->regs, /* chroma_qp_index_offset = */ 4);

	put_bits(c->regs, /* deblocking_filter_control_present_flag = */ 1, 1);
	put_bits(c->regs, /* constrained_intra_pred_flag = */ 0, 1);
	put_bits(c->regs, /* redundant_pic_cnt_present_flag = */ 0, 1);

	put_rbsp_trailing_bits(c->regs);
}

static void put_slice_header(h264enc *c)
{
	if (c->current_slice_type == SLICE_I)
		put_start_code(c->regs, 3, 5);
	else
		put_start_code(c->regs, 2, 1);

	put_ue(c->regs, /* first_mb_in_slice = */ 0);
	put_ue(c->regs, c->current_slice_type);
	put_ue(c->regs, /* pic_parameter_set_id = */ 0);

	put_bits(c->regs, c->current_frame_num & 0xf, 4);

	if (c->current_slice_type == SLICE_I)
		put_ue(c->regs, /* idr_pic_id = */ 0);

	if (c->current_slice_type == SLICE_P)
	{
		put_bits(c->regs, /* num_ref_idx_active_override_flag = */ 0, 1);
		put_bits(c->regs, /* ref_pic_list_modification_flag_l0 = */ 0, 1);
		put_bits(c->regs, /* adaptive_ref_pic_marking_mode_flag = */ 0, 1);
		if (c->entropy_coding_mode_flag)
			put_ue(c->regs, /* cabac_init_idc = */ 0);
	}

	if (c->current_slice_type == SLICE_I)
	{
		put_bits(c->regs, /* no_output_of_prior_pics_flag = */ 0, 1);
		put_bits(c->regs, /* long_term_reference_flag = */ 0, 1);
	}

	put_se(c->regs, /* slice_qp_delta = */ 0);

	put_ue(c->regs, /* disable_deblocking_filter_idc = */ 0);
	put_se(c->regs, /* slice_alpha_c0_offset_div2 = */ 0);
	put_se(c->regs, /* slice_beta_offset_div2 = */ 0);
}

void h264enc_free(h264enc *c)
{
	int i;

	ve_free(c->extra_buffer_line);
	ve_free(c->extra_buffer_frame);
	for (i = 0; i < 2; i++)
	{
		ve_free(c->ref_picture[i].luma_buffer);
		ve_free(c->ref_picture[i].extra_buffer);
	}
	ve_free(c->bytestream_buffer);
	ve_free(c->luma_buffer);
	free(c);
}

h264enc *h264enc_new(const struct h264enc_params *p)
{
	h264enc *c;
	int i;
	void *a;
	struct ve_mem *m;

	/* check parameter validity */
	if (!IS_ALIGNED(p->src_width, 16) || !IS_ALIGNED(p->src_height, 16) ||
		!IS_ALIGNED(p->width, 2) || !IS_ALIGNED(p->height, 2) ||
		p->width > p->src_width || p->height > p->src_height)
	{
		MSG("invalid picture size");
		return NULL;
	}

	if (p->qp == 0 || p->qp > 47)
	{
		MSG("invalid QP");
		return NULL;
	}

	if (p->src_format != H264_FMT_NV12 && p->src_format != H264_FMT_NV16)
	{
		MSG("invalid color format");
		return NULL;
	}

	/* allocate memory for h264enc structure */
	c = calloc(1, sizeof(*c));
	if (c == NULL)
	{
		MSG("can't allocate h264enc data");
		return NULL;
	}

	/* copy parameters */
	c->mb_width = DIV_ROUND_UP(p->width, 16);
	c->mb_height = DIV_ROUND_UP(p->height, 16);
	c->mb_stride = p->src_width / 16;

	c->crop_right = (c->mb_width * 16 - p->width) / 2;
	c->crop_bottom = (c->mb_height * 16 - p->height) / 2;

	c->profile_idc = p->profile_idc;
	c->level_idc = p->level_idc;

	c->entropy_coding_mode_flag = p->entropy_coding_mode ? 1 : 0;
	c->pic_init_qp = p->qp;
	c->keyframe_interval = p->keyframe_interval;

	c->write_sps_pps = 1;
	c->current_frame_num = 0;

	/* allocate input buffer */
	c->input_color_format = p->src_format;
	switch (c->input_color_format)
	{
	case H264_FMT_NV12:
		c->input_buffer_size = p->src_width * (p->src_height + p->src_height / 2);
		break;
	case H264_FMT_NV16:
		c->input_buffer_size = p->src_width * p->src_height * 2;
		break;
	}

	c->luma_buffer = ve_malloc(c->input_buffer_size);
	if (c->luma_buffer == NULL)
		goto nomem;

	a = c->luma_buffer->virt + p->src_width * p->src_height;
	m = malloc(sizeof(struct ve_mem));
	if (m == NULL)
		goto nomem;
	
	m->virt = a;
	m->phys = ve_virt2phys(a);
	c->chroma_buffer = m;//c->luma_buffer->virt + p->src_width * p->src_height;

	/* allocate bytestream output buffer */
	c->bytestream_buffer_size = 1 * 1024 * 1024;
	c->bytestream_buffer = ve_malloc(c->bytestream_buffer_size);
	if (c->bytestream_buffer == NULL)
		goto nomem;

	/* allocate reference picture memory */
	unsigned int luma_size = ALIGN(c->mb_width * 16, 32) * ALIGN(c->mb_height * 16, 32);
	unsigned int chroma_size = ALIGN(c->mb_width * 16, 32) * ALIGN(c->mb_height * 8, 32);
	for (i = 0; i < 2; i++)
	{
		c->ref_picture[i].luma_buffer = ve_malloc(luma_size + chroma_size);
		a = c->ref_picture[i].luma_buffer->virt + luma_size;
		m = malloc(sizeof(struct ve_mem));
		if (m == NULL)
			goto nomem;
		m->virt = a;
		m->phys = ve_virt2phys(a);
		c->ref_picture[i].chroma_buffer = m;//c->ref_picture[i].luma_buffer->virt + luma_size;
		
		c->ref_picture[i].extra_buffer = ve_malloc(luma_size / 4);
		if (c->ref_picture[i].luma_buffer == NULL || c->ref_picture[i].extra_buffer == NULL)
			goto nomem;
	}

	/* allocate unknown purpose buffers */
	c->extra_buffer_frame = ve_malloc(ALIGN(c->mb_width, 4) * c->mb_height * 8);
	c->extra_buffer_line = ve_malloc(c->mb_width * 32);
	if (c->extra_buffer_frame == NULL || c->extra_buffer_line == NULL)
		goto nomem;

	return c;

nomem:
	MSG("can't allocate VE memory");
	h264enc_free(c);
	return NULL;
}

void *h264enc_get_input_buffer(const h264enc *c)
{
	return c->luma_buffer->virt;
}

void *h264enc_get_bytestream_buffer(const h264enc *c)
{
	return c->bytestream_buffer->virt;
}

unsigned int h264enc_get_bytestream_length(const h264enc *c)
{
	return c->bytestream_length;
}

int h264enc_encode_picture(h264enc *c)
{
	c->current_slice_type = c->current_frame_num ? SLICE_P : SLICE_I;

	c->regs = ve_get(VE_ENGINE_AVC, 0);

	/* flush buffers (output because otherwise we might read old data later) */
	ve_flush_cache(c->bytestream_buffer);
	ve_flush_cache(c->luma_buffer);

	/* set output buffer */
	writel(0x0, c->regs + VE_AVC_VLE_OFFSET);
	writel(c->bytestream_buffer->phys, c->regs + VE_AVC_VLE_ADDR);
	writel(c->bytestream_buffer->phys + c->bytestream_buffer_size - 1, c->regs + VE_AVC_VLE_END);
	writel(c->bytestream_buffer_size * 8, c->regs + VE_AVC_VLE_MAX);

	/* write headers */
	if (c->write_sps_pps)
	{
		put_seq_parameter_set(c);
		put_pic_parameter_set(c);
		c->write_sps_pps = 0;
	}
	put_slice_header(c);

	/* set input size */
	writel(c->mb_stride << 16, c->regs + VE_ISP_INPUT_STRIDE);
	writel((c->mb_width << 16) | (c->mb_height << 0), c->regs + VE_ISP_INPUT_SIZE);

	/* set input format */
	writel(c->input_color_format << 29, c->regs + VE_ISP_CTRL);

	/* set input buffer */
	writel(c->luma_buffer->phys, c->regs + VE_ISP_INPUT_LUMA);
	writel(c->chroma_buffer->phys, c->regs + VE_ISP_INPUT_CHROMA);
	
	/* set reconstruction buffers */
	struct h264enc_ref_pic *ref_pic = &c->ref_picture[c->current_frame_num % 2];
	writel(ref_pic->luma_buffer->phys, c->regs + VE_AVC_REC_LUMA);
	writel(ref_pic->chroma_buffer->phys, c->regs + VE_AVC_REC_CHROMA);
	writel(ref_pic->extra_buffer->phys, c->regs + VE_AVC_REC_SLUMA);

	/* set reference buffers */
	if (c->current_slice_type != SLICE_I)
	{
		ref_pic = &c->ref_picture[(c->current_frame_num + 1) % 2];
		writel(ref_pic->luma_buffer->phys, c->regs + VE_AVC_REF_LUMA);
		writel(ref_pic->chroma_buffer->phys, c->regs + VE_AVC_REF_CHROMA);
		writel(ref_pic->extra_buffer->phys, c->regs + VE_AVC_REF_SLUMA);
	}

	/* set unknown purpose buffers */
	writel(c->extra_buffer_line->phys, c->regs + VE_AVC_MB_INFO);
	writel(c->extra_buffer_frame->phys, c->regs + VE_AVC_UNK_BUF);
	
	/* enable interrupt and clear status flags */
	writel(readl(c->regs + VE_AVC_CTRL) | 0xf, c->regs + VE_AVC_CTRL);
	writel(readl(c->regs + VE_AVC_STATUS) | 0x7, c->regs + VE_AVC_STATUS);

	/* set encoding parameters */
	uint32_t params = 0x0;
	if (c->entropy_coding_mode_flag)
		params |= 0x100;
	if (c->current_slice_type == SLICE_P)
		params |= 0x10;
	writel(params, c->regs + VE_AVC_PARAM);
	writel((4 << 16) | (c->pic_init_qp << 8) | c->pic_init_qp, c->regs + VE_AVC_QP);
	writel(0x00000104, c->regs + VE_AVC_MOTION_EST);

	/* trigger encoding */
	writel(0x8, c->regs + VE_AVC_TRIGGER);
	ve_wait(1);

	/* check result */
	uint32_t status = readl(c->regs + VE_AVC_STATUS);
	writel(status, c->regs + VE_AVC_STATUS);

	/* save bytestream length */
	c->bytestream_length = readl(c->regs + VE_AVC_VLE_LENGTH) / 8;

	/* next frame */
	c->current_frame_num++;
	if (c->current_frame_num >= c->keyframe_interval)
		c->current_frame_num = 0;

	ve_put();

	return (status & 0x3) == 0x1;
}

