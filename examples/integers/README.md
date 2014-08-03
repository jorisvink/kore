Test the http_argument_get_*() integer functions.

Run:
	# kore run

Test:
	# curl -i -k https://127.0.0.1:8888/?id=123123
	# curl -i -k https://127.0.0.1:8888/?id=-123123

The correct integer types should only be represented in the output.
