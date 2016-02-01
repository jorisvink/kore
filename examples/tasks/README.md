Kore task example.

This example creates an asynchronous task from the page handler
that performs a POST to the same server and fetches its data
before returning to the client.

Build:
```
	$ kore build
```

Run:
```
	$ kore run
```

Test:
```
	$ curl -i -k https://127.0.0.1:8888/?user=astring
	The returned data must match what you supplied in user ([a-z] string)
```
