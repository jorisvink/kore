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

# Using kore websockets via python.

import kore

#
# Our connection callback, gets called for each new websocket connection.
#
def onconnect(c):
	kore.log(kore.LOG_INFO, "%s: py connected" % c)

#
# Each websocket arriving on a connection triggers this function.
#
# It receives the connection object, the opcode (TEXT/BINARY) and the
# actual data received.
#
# In this example we use the websocket_broadcast() method from kore to
# simply relay the message to all other connection clients.
#
# If you want to send data directly back to the connection you can
# use kore.websocket_send(connection, op, data)
#
def onmessage(c, op, data):
	kore.websocket_broadcast(c, op, data, kore.WEBSOCKET_BROADCAST_GLOBAL)
	#c.websocket_send(op, data)

#
# Called for every connection that goes byebye.
#
def ondisconnect(c):
	kore.log(kore.LOG_INFO, "%s: py disconnecting" % c)

#
# The /ws connection handler. It establishes the websocket connection
# after a request was made for it.
#
# Note that the websocket_handshake() method for the request takes 3
# parameters which are the connection callback, message callback and
# disconnect callback.
#
# These are given as strings to Kore which will then resolve them
# in all modules which means you can give native callbacks here as well.
#
def ws_connect(req):
	try:
		req.websocket_handshake("onconnect", "onmessage", "ondisconnect")
	except:
		req.response(500, b'')
