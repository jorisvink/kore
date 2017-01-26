# Simplistic kore example

import kore
import json

def python_auth(req, data):
#	print("python auth called %s" % data)
	return kore.RESULT_OK

def python_validator(req, data):
	print("python validator called %s" % data)
	return kore.RESULT_OK

def onload(action):
	kore.log(kore.LOG_INFO, "FOOBAR python onload called with %d" % action)
	return kore.RESULT_OK

def kore_onload():
	print("kore_onload called")

def kore_preload():
	print("kore_preload called")

def page(req):
	print("%s path is %s - host is %s" % (req, req.path, req.host))
	print("connection is %s" % req.connection)
	xframe = req.request_header("xframe")
	if xframe != None:
		print("xframe header present %s" % xframe)
	if req.method == kore.METHOD_POST:
		try:
			length, body = req.body_read(1024)
			print("POST and got %d bytes! (%s)" %
			    (length, body.decode("utf-8")))
		except RuntimeError as r:
			print("oops runtime error %s" % r)
			req.response(500, b'')
		except:
			print("oops other error")
			req.response(500, b'')
		else:
			req.response_header("content-type", "text/plain")
			req.response(200, body)
	else:
		req.populate_get()
		id = req.argument("id")
		if id != None:
			print("got id of %s" % id)
		req.response_header("content-type", "text/plain")
		req.response(200, "hello 1234".encode("utf-8"))
	return kore.RESULT_OK

def json_parse(req):
	if req.method != kore.METHOD_PUT:
		req.response(400, b'')
		return kore.RESULT_OK

	data = json.loads(req.body)
	print("loaded json %s" % data)
	if data["hello"] == 123:
		print("hello is 123!")

	req.response(200, "ok".encode("utf-8"))
	return kore.RESULT_OK

def state_test(req):
	# If we don't have a state this is the first time we're called.
	if req.state is None:
		print("state_test: first time")
		req.state = "hello world"

		# Tell Kore to call us again next event loop.
		return kore.RESULT_RETRY

	# We have been called before.
	print("state_test: second time, with %s" % req.state)
	req.response(200, req.state.encode("utf-8"))

	# We *MUST* reset state back to None before returning RESULT_OK
	req.state = None;

	return kore.RESULT_OK

def minimal(req):
	req.response(200, b'')
	return kore.RESULT_OK
