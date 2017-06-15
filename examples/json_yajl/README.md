This example demonstrates how you can use external libs in your application.

In this case we link against yajl (Yet Another JSON library) in order to
parse a JSON string that was POSTed to the server.

Take a peek at conf/build.conf for different build flavors and how to
link to other libraries.

Run:
```
	$ kodev run
```

Test:
```
	$ curl -i -k -d '{"foo":{"bar": "Hello world"}}' https://127.0.0.1:8888
```

The result should echo back the foo.bar JSON path value: Hello world.

The yajl repo is available @ https://github.com/lloyd/yajl
