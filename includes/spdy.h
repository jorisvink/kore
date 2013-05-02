/*
 * Copyright (c) 2013 Joris Vink <joris@coders.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __H_SPDY_H
#define __H_SPDY_H

struct spdy_ctrl_frame {
	u_int16_t	version;
	u_int16_t	type;
	u_int8_t	flags;
	u_int32_t	length;
};

struct spdy_data_frame {
	u_int32_t	stream_id;
	u_int8_t	flags;
	u_int32_t	length;
};

struct spdy_syn_stream {
	u_int32_t	stream_id;
	u_int32_t	assoc_stream_id;
	u_int8_t	slot;
	u_int8_t	reserved;
	u_int8_t	prio;
};

struct spdy_header_block {
	u_int8_t	*header_block;
	u_int32_t	header_block_len;
	u_int32_t	header_offset;
	u_int32_t	header_pairs;
};

struct spdy_stream {
	u_int32_t	stream_id;
	u_int8_t	flags;
	u_int8_t	prio;

	struct spdy_header_block	*hblock;

	TAILQ_ENTRY(spdy_stream)	list;
};

extern const unsigned char SPDY_dictionary_txt[];

#define KORE_SSL_PROTO_STRING		"\x06spdy/3\x08http/1.1"
#define SPDY_CONTROL_FRAME(x)		((x & (1 << 31)))

#define SPDY_FRAME_SIZE			8
#define SPDY_SYNFRAME_SIZE		10
#define SPDY_ZLIB_DICT_SIZE		1423
#define SPDY_ZLIB_CHUNK			16348

/* control frames */
#define SPDY_CTRL_FRAME_SYN_STREAM	1
#define SPDY_CTRL_FRAME_SYN_REPLY	2
#define SPDY_CTRL_FRAME_SETTINGS	4
#define SPDY_CTRL_FRAME_PING		6
#define SPDY_CTRL_FRAME_WINDOW		9
#define SPDY_DATA_FRAME			99

/* flags */
#define FLAG_FIN			0x01
#define FLAG_UNIDIRECTIONAL		0x02

#define SPDY_HBLOCK_NORMAL		0
#define SPDY_HBLOCK_DELAYED_ALLOC	1

#endif /* !__H_SPDY_H */
