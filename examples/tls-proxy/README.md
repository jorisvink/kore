Kore as a TLS-proxy.

Note that this example requires a Kore binary built with NOHTTP set to 1.

Edit src/proxy.c and update PROXY_HOST and PROXY_PORT to match your needs.

Run:
```
	$ kore run
```

Test:
```
	Connect to the server and notice that it proxies data between you
	and your destination.

	$ openssl s_client -connect 127.0.0.1:8888
```
