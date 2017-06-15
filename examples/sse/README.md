This example demonstrates SSE (Server Side Events) in Kore.

Run:
```
	$ kodev run
```

Test (run different times to see the events broadcast):
```
	curl -H 'accept: text/event-stream' -ik https://127.0.0.1:8888/subscribe
```

If you point a browser to https://127.0.0.1:8888 you will see
a small log of what events are arriving.
