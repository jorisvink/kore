Kore example of tasks and websockets.

This example connects Kore via task to a named unix pipe and
spews out any output to all connected websocket clients.

Before you run this make the pipe:
       $ mkfifo /tmp/pipe

Run:
```
	$ kodev run
```

Test:
```
	Open a browser that does websockets, surf to https://127.0.0.1:8888
	or whatever configured IP you have in the config.

	Hit the connect button to open a websocket session.

	Now connect a writer endpoint to the named pipe (/tmp/pipe):
		$ echo "hello" > /tmp/pipe

	You should see the result in your browser.
```
