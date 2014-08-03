#include <kore/kore.h>
#include <kore/http.h>

int		page(struct http_request *);

int
page(struct http_request *req)
{
	int16_t			s16;
	u_int16_t		u16;
	int32_t			s32;
	int64_t			s64;
	u_int64_t		u64;
	struct kore_buf		*buf;
	u_int32_t		u32, len;
	u_int8_t		c, *data;

	http_populate_arguments(req);
	buf = kore_buf_create(128);

	if (http_argument_get_byte("id", &c))
		kore_buf_appendf(buf, "byte\t%c\n", c);

	if (http_argument_get_int16("id", &s16))
		kore_buf_appendf(buf, "int16\t%d\n", s16);

	if (http_argument_get_uint16("id", &u16))
		kore_buf_appendf(buf, "uint16\t%d\n", u16);

	if (http_argument_get_int32("id", &s32))
		kore_buf_appendf(buf, "int32\t%d\n", s32);

	if (http_argument_get_uint32("id", &u32))
		kore_buf_appendf(buf, "uint32\t%d\n", u32);

	if (http_argument_get_int64("id", &s64))
		kore_buf_appendf(buf, "int64\t%ld\n", s64);

	if (http_argument_get_uint64("id", &u64))
		kore_buf_appendf(buf, "uint64\t%lu\n", u64);

	data = kore_buf_release(buf, &len);
	http_response(req, 200, data, len);
	kore_mem_free(data);

	return (KORE_RESULT_OK);
}
