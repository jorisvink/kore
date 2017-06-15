#
# Copyright (c) 2017 Joris Vink <joris@coders.se>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

# This is a simple python module that can be loaded into Kore.
# It demonstrates some basic abilities to deal with HTTP requests.

# Pull in the kore stuff.
import kore

# Pull in python JSON parsing.
import json

#
# A validator that the configuration for this application uses to determine
# if a request fulfills the requirements to pass an authentication block.
#
# See the configuration for more.
#
def python_auth(req, data):
	kore.log(kore.LOG_NOTICE, "python auth called %s" % data)
	return kore.RESULT_OK

#
# Define a validator that kore can use via the configuration to validate
# something before allowing access to it.
#
def python_validator(req, data):
	kore.log(kore.LOG_NOTICE, "python validator called %s" % data)
	return kore.RESULT_OK

#
# This function is called when our python module is loaded/unloaded.
# The action param is kore.MODULE_LOAD or kore.MODULE_UNLOAD respectively.
#
def onload(action):
	kore.log(kore.LOG_INFO, "python module onload called with %d!" % action)
	return kore.RESULT_OK

# Called by Kore when the parent is starting.
def kore_parent_configure():
	# Listen on an additional interface and port.
	kore.listen("127.0.0.1", "8889", "")
	kore.log(kore.LOG_INFO, "kore_parent_configure called!")

# Called by Kore when the worker is starting.
def kore_worker_configure():
	kore.log(kore.LOG_INFO, "kore_worker_configure called!")

#
# Test page handler that displays some debug information as well as
# fetches the "xframe" header from the request and logs it if present.
#
# If the request is a POST then we read the body up to 1024 bytes in
# one go and display the result and bytes read in the log.
#
# If it's a GET request attempts to find the "id" argument and presents
# it to the user.
#
def page(req):
	kore.log(kore.LOG_INFO,
	    "%s path is %s - host is %s" % (req, req.path, req.host))
	kore.log(kore.LOG_INFO, "connection is %s" % req.connection)
	xframe = req.request_header("xframe")
	if xframe != None:
		kore.log(kore.LOG_INFO, "xframe header present: '%s'" % xframe)
	if req.method == kore.METHOD_POST:
		try:
			length, body = req.body_read(1024)
			kore.log(kore.LOG_INFO, "POST and got %d bytes! (%s)" %
			    (length, body.decode("utf-8")))
		except RuntimeError as r:
			kore.log(kore.LOG_INFO, "oops runtime error %s" % r)
			req.response(500, b'')
		except:
			kore.log(kore.LOG_INFO, "oops other error")
			req.response(500, b'')
		else:
			req.response_header("content-type", "text/plain")
			req.response(200, body)
	else:
		req.populate_get()
		id = req.argument("id")
		if id != None:
			kore.log(kore.LOG_INFO, "got id of %s" % id)
		req.response_header("content-type", "text/plain")
		req.response(200, "hello 1234".encode("utf-8"))

#
# Handler that parses the incoming body as JSON and dumps out some things.
#
def json_parse(req):
	if req.method != kore.METHOD_PUT:
		req.response(400, b'')
	else:
		data = json.loads(req.body)
		kore.log(kore.LOG_INFO, "loaded json %s" % data)
		if data["hello"] == 123:
			kore.log(kore.LOG_INFO, "hello is 123!")

		req.response(200, "ok".encode("utf-8"))

#
# Small handler, returns 200 OK.
#
def minimal(req):
	req.response(200, b'')

#
# Small handler that grabs a cookie if set.
#
def kaka(req):
	req.populate_cookies()
	cookie = req.cookie("hello")
	if cookie is not None:
		kore.log(kore.LOG_INFO, "got hello with value %s" % cookie)
	req.response(200, b'')
