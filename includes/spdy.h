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

#define KORE_SSL_PROTO_STRING	"\x06spdy/3\x08http/1.1"

struct spdy_frame {
	u_int32_t	frame_1;
	u_int32_t	frame_2;
};

struct spdy_ctrl_frame {
	int		type:16;
	int		version:15;
	int		control_bit:1;
	int		length:24;
	int		flags:8;
};

struct spdy_data_frame {
	int		stream_id:31;
	int		control_bit:1;
	int		length:24;
	int		flags:8;
};

struct spdy_syn_stream {
	u_int32_t	stream_id;
	u_int32_t	assoc_stream_id;
	u_int8_t	slot;
	int		reserved:5;
	int		prio:3;
};

#define SPDY_CONTROL_FRAME(x)		((x->frame_1 & (1 << 31)))
#define SPDY_FRAME_SIZE			8

/* control frames. */
#define SPDY_CTRL_FRAME_SYN_STREAM	1
#define SPDY_CTRL_FRAME_SETTINGS	4

/* flags. */
#define FLAG_FIN			0x01
#define FLAG_UNIDIRECTIONAL		0x02

#endif /* !__H_SPDY_H */
