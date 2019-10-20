Native Kore JSON parser example.

Run:
```
	$ kodev run
```

Test:
```
	$ curl -i -k -d '{"foo":{"bar": "Hello world"}}' https://127.0.0.1:8888
```

The result should echo back the foo.bar JSON path value if it is a JSON string.
