Test parameter to integer conversions.

Run:
```
	$ kodev run
```

Test:
```
	$ curl -i -k https://127.0.0.1:8888/?id=123123
	$ curl -i -k https://127.0.0.1:8888/?id=-123123
```

The correct integer types should only be represented in the output.
