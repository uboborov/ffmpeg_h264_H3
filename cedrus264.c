/*
 * Cedrus 264 Video Encoder
 * Copyright (c) 2014 Julien Folly
 *
 * This file is part of Libav.
 *
 * Libav is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Libav is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Libav; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * @file
 * Cedrus 264 Encoder
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "libavutil/internal.h"
#include "libavutil/opt.h"
#include "libavutil/mem.h"
#include "libavutil/pixdesc.h"
#include "avcodec.h"
#include "internal.h"

#include "arm/sunxi/ve.h"

/* byte stream utils from:
 * https://github.com/jemk/cedrus/tree/master/h264enc
 */
static void put_bits(void* regs, uint32_t x, int num)
{
	writel(x, (uint8_t *)regs + VE_AVC_BASIC_BITS);
	writel(0x1 | ((num & 0x1f) << 8), (uint8_t *)regs + VE_AVC_TRIGGER);
	// again the problem, how to check for finish?
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

static void put_start_code(void* regs)
{
	uint32_t tmp = readl((uint8_t *)regs + VE_AVC_PARAM);

	/* Disable emulation_prevention_three_byte */
	writel(tmp | (0x1 << 31), (uint8_t *)regs + VE_AVC_PARAM);

	put_bits(regs, 0, 31);
	put_bits(regs, 1, 1);

	writel(tmp, (uint8_t *)regs + VE_AVC_PARAM);
}

static void put_rbsp_trailing_bits(void* regs)
{
	unsigned int cur_bs_len = readl((uint8_t *)regs + VE_AVC_VLE_LENGTH);

	int num_zero_bits = 8 - ((cur_bs_len + 1) & 0x7);
	put_bits(regs, 1 << num_zero_bits, num_zero_bits + 1);
}

static void put_seq_parameter_set(void* regs, int width, int height)
{
	put_bits(regs, 3 << 5 | 7 << 0, 8);	// NAL Header
	put_bits(regs, 77, 8);			// profile_idc
	put_bits(regs, 0x0, 8);			// constraints
	put_bits(regs, 4 * 10 + 1, 8);		// level_idc
	put_ue(regs, 0);			// seq_parameter_set_id

	put_ue(regs, 0);			// log2_max_frame_num_minus4
	put_ue(regs, 0);			// pic_order_cnt_type
	// if (pic_order_cnt_type == 0)
		put_ue(regs, 4);		// log2_max_pic_order_cnt_lsb_minus4

	put_ue(regs, 1);			// max_num_ref_frames
	put_bits(regs, 0, 1);			// gaps_in_frame_num_value_allowed_flag

	put_ue(regs, width - 1);		// pic_width_in_mbs_minus1
	put_ue(regs, height - 1);		// pic_height_in_map_units_minus1

	put_bits(regs, 1, 1);			// frame_mbs_only_flag
	// if (!frame_mbs_only_flag)

	put_bits(regs, 1, 1);			// direct_8x8_inference_flag
	put_bits(regs, 0, 1);			// frame_cropping_flag
	// if (frame_cropping_flag)

	put_bits(regs, 0, 1);			// vui_parameters_present_flag
	// if (vui_parameters_present_flag)
}

static void put_pic_parameter_set(void *regs, int qp_minus30)
{
	put_bits(regs, 3 << 5 | 8 << 0, 8);	// NAL Header
	put_ue(regs, 0);			// pic_parameter_set_id
	put_ue(regs, 0);			// seq_parameter_set_id
	put_bits(regs, 1, 1);			// entropy_coding_mode_flag
	put_bits(regs, 0, 1);			// bottom_field_pic_order_in_frame_present_flag
	put_ue(regs, 0);			// num_slice_groups_minus1
	// if (num_slice_groups_minus1 > 0)

	put_ue(regs, 0);			// num_ref_idx_l0_default_active_minus1
	put_ue(regs, 0);			// num_ref_idx_l1_default_active_minus1
	put_bits(regs, 0, 1);			// weighted_pred_flag
	put_bits(regs, 0, 2);			// weighted_bipred_idc
	//put_se(regs, 0);			// pic_init_qp_minus26 (minus slice_qp_delta)
	//put_se(regs, 0);			// pic_init_qs_minus26
	put_se(regs, qp_minus30);		// pic_init_qp_minus26 (minus slice_qp_delta)
	put_se(regs, qp_minus30);		// pic_init_qs_minus26
	put_se(regs, 4);			// chroma_qp_index_offset
	put_bits(regs, 1, 1);			// deblocking_filter_control_present_flag
	put_bits(regs, 0, 1);			// constrained_intra_pred_flag
	put_bits(regs, 0, 1);			// redundant_pic_cnt_present_flag
}

static void put_slice_header(void* regs)
{
	put_bits(regs, 3 << 5 | 5 << 0, 8);	// NAL Header

	put_ue(regs, 0);			// first_mb_in_slice
	put_ue(regs, 2);			// slice_type
	put_ue(regs, 0);			// pic_parameter_set_id
	put_bits(regs, 0, 4);			// frame_num

	// if (IdrPicFlag)
		put_ue(regs, 0);		// idr_pic_id

	// if (pic_order_cnt_type == 0)
		put_bits(regs, 0, 8);		// pic_order_cnt_lsb

	// dec_ref_pic_marking
		put_bits(regs, 0, 1);		// no_output_of_prior_pics_flag
		put_bits(regs, 0, 1);		// long_term_reference_flag

	put_se(regs, 4);			// slice_qp_delta

	// if (deblocking_filter_control_present_flag)
		put_ue(regs, 0);		// disable_deblocking_filter_idc
		// if (disable_deblocking_filter_idc != 1)
			put_se(regs, 0);	// slice_alpha_c0_offset_div2
			put_se(regs, 0);	// slice_beta_offset_div2
}

static void put_aud(void* regs)
{
	put_bits(regs, 0 << 5 | 9 << 0, 8);	// NAL Header

	put_bits(regs, 7, 3);			// primary_pic_type
}

#define CEDAR_OUTPUT_BUF_SIZE	1*1024*1024
typedef struct cedrus264Context {
	AVClass *class;
	uint8_t *ve_regs;
	struct ve_mem *input_buf, *output_buf, *reconstruct_buf, *small_luma_buf, *mb_info_buf;
	unsigned int tile_w, tile_w2, tile_h, tile_h2, mb_w, mb_h, plane_size, frame_size;
	unsigned int frame_num;
	int qp, vewait;
} cedrus264Context;

static av_cold int cedrus264_encode_init(AVCodecContext *avctx)
{
	cedrus264Context *c4 = avctx->priv_data;
	
	/* Check pixel format */
	if(avctx->pix_fmt != AV_PIX_FMT_NV12){
		av_log(avctx, AV_LOG_FATAL, "Unsupported pixel format (use -pix_fmt nv12)!\n");
		return AVERROR(EINVAL);
	}

	/* Check width */
	if(avctx->width % 32 != 0){
		av_log(avctx, AV_LOG_FATAL, "Input width is not a multiple of 32!\n");
		return AVERROR(EINVAL);
	}

	/* Check if VE is available */
	while(!ve_lock()){
		if (c4->vewait <= 0){
			av_log(avctx, AV_LOG_ERROR, "VE in use!\n");
			return AVERROR(ENOMEM);
		}
		av_log(avctx, AV_LOG_INFO, "VE in use, wait %i seconds.\r", c4->vewait--);
		sleep(1);
	}

	/* Open VE */
	if(!ve_open()){
		av_log(avctx, AV_LOG_ERROR, "VE Open error.\n");
		return AVERROR(ENOMEM);
	}
	

	/* Compute tile, macroblock and plane size */
	c4->tile_w = (avctx->width + 31) & ~31;
	c4->tile_w2 = (avctx->width / 2 + 31) & ~31;
	c4->tile_h = (avctx->height + 31) & ~31;
	c4->tile_h2 = (avctx->height / 2 + 31) & ~31;
	c4->mb_w = (avctx->width + 15) / 16;
	c4->mb_h = (avctx->height + 15) / 16;
	c4->plane_size = c4->mb_w * 16 * c4->mb_h * 16;
	c4->frame_size = c4->plane_size + c4->plane_size / 2;

	/* Alloc buffers */
	c4->input_buf = ve_malloc(c4->frame_size);
	c4->output_buf = ve_malloc(CEDAR_OUTPUT_BUF_SIZE);
	c4->reconstruct_buf = ve_malloc(c4->tile_w * c4->tile_h + c4->tile_w * c4->tile_h2);
	c4->small_luma_buf = ve_malloc(c4->tile_w2 * c4->tile_h2);
	c4->mb_info_buf = ve_malloc(0x1000);
	if(!c4->input_buf || !c4->output_buf || !c4->reconstruct_buf || !c4->small_luma_buf || !c4->mb_info_buf){
		av_log(avctx, AV_LOG_FATAL, "Cannot allocate frame.\n");
		return AVERROR(ENOMEM);
	}

	/* Activate AVC engine */
	c4->ve_regs = ve_get(VE_ENGINE_AVC, 0);

	/* ---- Part to put in cedrus264_encode if engine is used by multiple process (Need to be checked) */

	/* Input size */
	writel(c4->mb_w << 16, c4->ve_regs + VE_ISP_INPUT_STRIDE);
	writel((c4->mb_w << 16) | (c4->mb_h << 0), c4->ve_regs + VE_ISP_INPUT_SIZE);

	/* Input buffer */
	writel(c4->input_buf->phys, c4->ve_regs + VE_ISP_INPUT_LUMA);
	writel(c4->input_buf->phys + c4->plane_size, c4->ve_regs + VE_ISP_INPUT_CHROMA);
	
	/* Reference output */
	writel(c4->reconstruct_buf->phys, c4->ve_regs + VE_AVC_REC_LUMA);
	writel(c4->reconstruct_buf->phys + c4->tile_w * c4->tile_h, c4->ve_regs + VE_AVC_REC_CHROMA);
	writel(c4->small_luma_buf->phys, c4->ve_regs + VE_AVC_REC_SLUMA);
	writel(c4->mb_info_buf->phys, c4->ve_regs + VE_AVC_MB_INFO);

	/* Encoding parameters */
	writel(0x00000100, c4->ve_regs + VE_AVC_PARAM);
	writel(0x00040000 | (c4->qp<<8) | c4->qp, c4->ve_regs + VE_AVC_QP);
	//writel(0x00041e1e, c4->ve_regs + VE_AVC_QP); // Fixed QP=30
	writel(0x00000104, c4->ve_regs + VE_AVC_MOTION_EST);

	/* ---- Part end ---- */

	/* Alloc Frame */
	avctx->coded_frame = av_frame_alloc();
	if(!avctx->coded_frame){
		av_log(avctx, AV_LOG_FATAL, "Cannot allocate frame.\n");
		return AVERROR(ENOMEM);
	}

	/* Init variables */
	c4->frame_num = 0;
	avctx->coded_frame->quality = c4->qp * FF_QP2LAMBDA;

	return 0;
}

static int cedrus264_encode(AVCodecContext *avctx, AVPacket *pkt,
                      const AVFrame *frame, int *got_packet)
{
	cedrus264Context *c4 = avctx->priv_data;
	unsigned int size;
	int result;

	/* Copy data */
	result = avpicture_layout((const AVPicture *)frame, PIX_FMT_NV12,
		avctx->width, avctx->height, c4->input_buf->virt, c4->frame_size);
 	if(result < 0){
		av_log(avctx, AV_LOG_ERROR, "Input buffer too small.\n");
		return AVERROR(ENOMEM);
	}
	ve_flush_cache(c4->input_buf);

	/* flush output buffer, otherwise we might read old cached data */
	ve_flush_cache(c4->output_buf);
	
	/* Set output buffer */
	writel(0x0, c4->ve_regs + VE_AVC_VLE_OFFSET);
	writel(c4->output_buf->phys, c4->ve_regs + VE_AVC_VLE_ADDR);
	writel(c4->output_buf->phys + CEDAR_OUTPUT_BUF_SIZE - 1, c4->ve_regs + VE_AVC_VLE_END);

	writel(0x04000000, c4->ve_regs + 0xb8c); // ???
	
	put_start_code(c4->ve_regs);
	put_aud(c4->ve_regs);
	put_rbsp_trailing_bits(c4->ve_regs);

	if (c4->frame_num == 0)
	{
		put_start_code(c4->ve_regs);
		put_seq_parameter_set(c4->ve_regs, c4->mb_w, c4->mb_h);
		put_rbsp_trailing_bits(c4->ve_regs);

		put_start_code(c4->ve_regs);
		put_pic_parameter_set(c4->ve_regs, c4->qp - 30);
		put_rbsp_trailing_bits(c4->ve_regs);
	}

	put_start_code(c4->ve_regs);
	put_slice_header(c4->ve_regs);

	writel(readl(c4->ve_regs + VE_AVC_CTRL) | 0xf, c4->ve_regs + VE_AVC_CTRL);
	writel(readl(c4->ve_regs + VE_AVC_STATUS) | 0x7, c4->ve_regs + VE_AVC_STATUS);

	writel(0x8, c4->ve_regs + VE_AVC_TRIGGER);
	ve_wait(1);

	writel(readl(c4->ve_regs + VE_AVC_STATUS), c4->ve_regs + VE_AVC_STATUS);

	size = readl(c4->ve_regs + VE_AVC_VLE_LENGTH) / 8;
	if(size > 0){
		if ((result = ff_alloc_packet(pkt, size)) < 0){
			av_log(avctx, AV_LOG_ERROR, "Packet allocation error.\n");
			return result;
		}
		memcpy(pkt->data, c4->output_buf->virt, size);

		pkt->pts = pkt->dts = frame->pts - ff_samples_to_time_base(avctx, avctx->delay);
		pkt->flags |= AV_PKT_FLAG_KEY;
		*got_packet = 1;
	}else *got_packet = 0;

	c4->frame_num++;

	return 0;
}

static av_cold int cedrus264_close(AVCodecContext *avctx)
{
	cedrus264Context *c4 = avctx->priv_data;

	/* Close AVC engine */
	ve_put();

	/* Free buffers */
	ve_free(c4->input_buf);
	ve_free(c4->output_buf);
	ve_free(c4->reconstruct_buf);
	ve_free(c4->small_luma_buf);
	ve_free(c4->mb_info_buf);

	/* Disable and close VE */
	ve_close();
	ve_unlock();

	/* Free Frame */
	av_frame_free(&avctx->coded_frame);

	return 0;
}

#define OFFSET(x) offsetof(cedrus264Context, x)
#define VE AV_OPT_FLAG_VIDEO_PARAM | AV_OPT_FLAG_ENCODING_PARAM
static const AVOption options[] = {
	 /* Quality range form 0 to 51 not working, good is between 2 and 47 */
	{ "qp",		"Constant quantization parameter rate control method", OFFSET(qp), AV_OPT_TYPE_INT, { .i64 = 30 }, 2, 47, VE },
	{ "vewait",	"Time to wait if the VE is busy (default 0)", OFFSET(vewait), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, INT_MAX, VE },
	{ NULL },
};

static const AVClass cedrus264_class = {
	.class_name = "cedrus264",
	.item_name  = av_default_item_name,
	.option     = options,
	.version    = LIBAVUTIL_VERSION_INT,
};

AVCodec ff_cedrus264_encoder = {
	.name           = "cedrus264",
	.long_name      = NULL_IF_CONFIG_SMALL("Cedrus H.264 Encoder"),
	.type           = AVMEDIA_TYPE_VIDEO,
	.id             = AV_CODEC_ID_H264,
	.priv_data_size = sizeof(cedrus264Context),
	.init           = cedrus264_encode_init,
	.encode2        = cedrus264_encode,
	.close          = cedrus264_close,
	.priv_class	= &cedrus264_class,
};
