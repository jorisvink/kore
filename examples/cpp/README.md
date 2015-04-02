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

In order to run this example with the default C++ settings (default compiler dialect, libstdc++):
```
	# kore run
```

In order to run with a specific dialect and C++ runtime:
```
	# env CXXSTD=c++11 CXXLIB=c++ kore run
```

You can also supply your own compiler combined with the above:
```
	# env CXX=clang++ CXXSTD=c++11 CXXLIB=c++ kore run
```
