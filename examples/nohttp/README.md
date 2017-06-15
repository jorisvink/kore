Kore NOHTTP example

Note that this example only works if Kore was built with NOHTTP=1.

Run:
```
	$ kodev run
```

Test:
```
	Connect to the server using openssl s_client, you will notice
	that anything sent is submitted back to your client.

	$ openssl s_client -connect 127.0.0.1:8888
```
