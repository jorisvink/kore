#include <kore/kore.h>
#include <kore/http.h>

int		page(struct http_request *);

int
page(struct http_request *req)
{
	float			fl;
	double			dbl;
	int16_t			s16;
	u_int16_t		u16;
	int32_t			s32;
	int64_t			s64;
	u_int64_t		u64;
	u_int32_t		u32;
	size_t			len;
	struct kore_buf		*buf;
	u_int8_t		c, *data;

	http_populate_get(req);
	buf = kore_buf_alloc(128);

	if (http_argument_get_byte(req, "id", &c))
		kore_buf_appendf(buf, "byte\t%c\n", c);

	if (http_argument_get_int16(req, "id", &s16))
		kore_buf_appendf(buf, "int16\t%d\n", s16);

	if (http_argument_get_uint16(req, "id", &u16))
		kore_buf_appendf(buf, "uint16\t%d\n", u16);

	if (http_argument_get_int32(req, "id", &s32))
		kore_buf_appendf(buf, "int32\t%d\n", s32);

	if (http_argument_get_uint32(req, "id", &u32))
		kore_buf_appendf(buf, "uint32\t%d\n", u32);

	if (http_argument_get_int64(req, "id", &s64))
		kore_buf_appendf(buf, "int64\t%ld\n", s64);

	if (http_argument_get_uint64(req, "id", &u64))
		kore_buf_appendf(buf, "uint64\t%lu\n", u64);

	if (http_argument_get_float(req, "id", &fl))
		kore_buf_appendf(buf, "float\t%g\n", fl);

	if (http_argument_get_double(req, "id", &dbl))
		kore_buf_appendf(buf, "double\t%g\n", dbl);

	data = kore_buf_release(buf, &len);
	http_response(req, 200, data, len);
	kore_free(data);

	return (KORE_RESULT_OK);
}
