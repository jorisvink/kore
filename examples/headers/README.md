Example on how to read HTTP request headers and set your own custom ones.

Run:
```
	# kodev run
```

Test:
```
	# curl -H "X-Custom-Header: testing" -i -k https://127.0.0.1:8888
```

If X-Custom-Header is given, it will be mirrored in the response.
