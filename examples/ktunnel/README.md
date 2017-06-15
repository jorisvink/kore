KTunnel (anything over HTTPS)

This example demonstrates how we can use Kore to create an
anything-over-HTTPS tunnel.

Build:
```
	# kodev build
```

Run:
```
	# kodev run
```

Test:
```
	# openssl s_client -connect 127.0.0.1:8888

	Then enter:

	GET /connect?host=74.125.232.248&port=80 HTTP/1.1
	Host: 127.0.0.1

	GET / HTTP/1.1
	Host: www.google.se

	(And hit enter)
```

You should see Kore connect to the google server given and
return the results back to you.

A client for OSX exists under the **client/** directory. It requires
you to link with -lssl and -lcrypto.
