#include <kore/kore.h>
#include <kore/http.h>

int	onload(int);
int	cpage(struct http_request *);
void	c_on_connect(struct connection *);
int	c_validator(struct http_request *, void *);

int
c_validator(struct http_request *req, void *data)
{
	printf("c_validator called!\n");
	return (KORE_RESULT_OK);
}

void
c_on_connect(struct connection *c)
{
	printf("c_on_connect!\n");
}

int
onload(int action)
{
	printf("C onload called!\n");
	return (KORE_RESULT_OK);
}

int
cpage(struct http_request *req)
{
	http_populate_get(req);

	//printf("cpage called\n");
	http_response(req, 200, NULL, 0);

	return (KORE_RESULT_OK);
}
