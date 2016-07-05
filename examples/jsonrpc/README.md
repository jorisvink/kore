This example demonstrates how you can use the JSON-RPC module in your
application.

Note that the module depends upon the third-party library `yajl` (Yet Another
JSON library) to parse and produce messages.

As for the `yajl_json` example, conf/build.conf shows how to link to the
library.

This example needs kore having been compiled with `JSONRPC` (and so `HTTP`)
activated.

Run:
```
	$ kore run
```

Test:
```
	$ curl -i -k \
	    -d '{"jsonrpc":"2.0","method":"echo","params":"Hello world"}' \
	    https://127.0.0.1:8888/v1
```
The result should echo back the string at `params`: Hello world.

Alternatively, if you have bats installed:
```
	$ bats test/integ/jsonrpc.bats
```
Will run a small test suite.


The yajl repo is available @ https://github.com/lloyd/yajl


Message Handling Log
--------------------

The `jsonrpc\_request` keeps a log of messages with levels similar to those of
syslog. Messages are added with jsonrpc_log().

By default messages of the log are added to the data member of the error
responses if at levels EMERG, ERROR, WARNING and NOTICE.

If you dont want log messages to be outputted zero the log_levels flag of the
jsonrpc_request.


Formatting responses
--------------------

By default responses are not prettyfied. To do that set the appropriate flag in
the jsonrpc_request structure.
