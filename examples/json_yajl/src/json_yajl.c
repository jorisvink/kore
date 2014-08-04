#include <kore/kore.h>
#include <kore/http.h>

#include <yajl/yajl_tree.h>

int		page(struct http_request *);

int
page(struct http_request *req)
{
	struct kore_buf		*buf;
	char			*body;
	yajl_val		node, v;
	char			eb[1024];
	const char		*path[] = { "foo", "bar", NULL };

	/* We only allow POST methods. */
	if (req->method != HTTP_METHOD_POST) {
		http_response(req, 400, NULL, 0);
		return (KORE_RESULT_OK);
	}

	/*
	 * Grab the entire body we received as text (NUL-terminated).
	 * Note: this can return NULL and the result MUST be freed.
	 */
	if ((body = http_post_data_text(req)) == NULL) {
		http_response(req, 400, NULL, 0);
		return (KORE_RESULT_OK);
	}

	/* Parse the body via yajl now. */
	node = yajl_tree_parse(body, eb, sizeof(eb));
	if (node == NULL) {
		if (strlen(eb)) {
			kore_log(LOG_NOTICE, "parse error: %s", eb);
		} else {
			kore_log(LOG_NOTICE, "parse error: unknown");
		}

		kore_mem_free(body);
		http_response(req, 400, NULL, 0);
		return (KORE_RESULT_OK);
	}

	buf = kore_buf_create(128);

	/* Attempt to grab foo.bar from the JSON tree. */
	v = yajl_tree_get(node, path, yajl_t_string);
	if (v == NULL) {
		kore_buf_appendf(buf, "no such path: foo.bar\n");
	} else {
		kore_buf_appendf(buf, "foo.bar = '%s'\n", YAJL_GET_STRING(v));
	}

	/* Release the JSON tree now. */
	yajl_tree_free(node);
	kore_mem_free(body);

	/* Respond to the client. */
	http_response(req, 200, buf->data, buf->offset);
	kore_buf_free(buf);

	return (KORE_RESULT_OK);
}
