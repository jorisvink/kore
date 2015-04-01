Kore example showing how to use C++ support!

All functions accessible to kore must have their prototypes wrapped with the extern keyword like so:
```
extern “C” {
	int pageA(struct http_request *);
	int pageB(struct http_request *);
	int validatorA(struct http_request *, char *);
}
```

You will also need to compile kore with the KORE_CPP_SUPPORT environment variable enabled:
```
	# env KORE_CPP_SUPPORT=1 make
```

Run:
```
	# kore run
```
